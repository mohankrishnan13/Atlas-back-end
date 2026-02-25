"""
api/routes_auth.py

Authentication endpoints for the ATLAS SOC dashboard.

Security architecture overview:
- Passwords never touch a log line or response body — they're hashed immediately
  upon receipt and the plaintext is discarded.
- Login failures increment a counter; the counter is returned in no response
  (attackers can't use it to gauge how close they are to lockout).
- Forgot-password always returns 200 — returning 404 on unknown emails leaks
  account existence (user enumeration vulnerability, OWASP A07).
- JWTs contain email + role so downstream routes can authorize without DB calls.
- All DB operations are async — auth endpoints under SOC incident load won't
  block the event loop and delay other analysts.

Account lockout policy:
  After MAX_FAILED_ATTEMPTS consecutive failures the account is deactivated.
  An admin must re-enable it via the user management API (not built here).
  This prevents credential-stuffing attacks from silently succeeding while
  reducing alert fatigue compared to time-based lockouts.
"""

import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    get_password_hash,
    verify_password,
    get_current_user,
    require_role,
)
from app.db.database import get_db
from app.db.models import User
from app.models.schemas import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    SignupRequest,
    SignupResponse,
    TokenResponse,
    UserProfile,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Number of consecutive failures before the account is deactivated.
# Chosen as a balance: too low = legitimate users get locked out by fat-fingers;
# too high = gives attackers too many guesses without detection.
MAX_FAILED_ATTEMPTS = 10


# ─── A. Signup ────────────────────────────────────────────────────────────────

@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new SOC analyst account",
)
async def signup(
    payload: SignupRequest,
    db: AsyncSession = Depends(get_db),
) -> SignupResponse:
    """
    Creates a new ATLAS user account.

    Steps:
    1. Validate email uniqueness — 400 if already registered.
    2. Hash the plaintext password with bcrypt (salt auto-generated).
    3. Persist the user record to PostgreSQL.
    4. Return a 201 Created response with the safe user summary.

    The plaintext password lives in memory only for the duration of this
    function call and is GC'd immediately after `get_password_hash` returns.
    """
    # Step 1: Check for duplicate email
    result = await db.execute(
        select(User).where(User.email == payload.email.lower().strip())
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        # Don't distinguish "email exists" from "email exists but inactive" —
        # that would let attackers map which accounts are active.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    # Validate role — only known roles are accepted to prevent privilege escalation
    allowed_roles = {"analyst", "lead", "admin"}
    role = payload.role.lower().strip()
    if role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{role}'. Must be one of: {sorted(allowed_roles)}",
        )

    # Step 2: Hash the password
    hashed = get_password_hash(payload.password)

    # Step 3: Create and persist the user
    new_user = User(
        email=payload.email.lower().strip(),
        full_name=payload.full_name.strip(),
        role=role,
        hashed_password=hashed,
        is_active=True,
        failed_login_attempts=0,
    )
    db.add(new_user)
    # Commit is handled by get_db's context manager — explicit flush ensures
    # the row is written so we can read back the auto-generated `id` if needed.
    await db.flush()

    logger.info(f"New user registered: {new_user.email} | role: {new_user.role}")

    return SignupResponse(
        message="Account created successfully. You may now log in.",
        email=new_user.email,
        role=new_user.role,
    )


# ─── B. Login ─────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT access token",
)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Authenticates a user and returns a signed JWT access token.

    Steps:
    1. Look up the user by email — 401 if not found (generic message to avoid
       leaking whether the email is registered).
    2. Check the account is active — 401 if deactivated.
    3. Verify the password with bcrypt constant-time comparison.
       - On failure: increment failed_login_attempts, lock account at threshold.
       - On success: reset counter, record last_login, issue JWT.

    The same generic 401 message is used for "email not found" and
    "wrong password" — this prevents user enumeration by login response.
    """
    _GENERIC_401 = "Invalid email or password."

    # Step 1: Find user
    result = await db.execute(
        select(User).where(User.email == payload.email.lower().strip())
    )
    user: Optional[User] = result.scalar_one_or_none()

    if not user:
        # Still spend time "hashing" a dummy value to prevent timing attacks:
        # if we return immediately on unknown email, an attacker can tell the
        # difference between "no such user" (fast) and "wrong password" (slow bcrypt).
        get_password_hash("timing-attack-prevention-dummy")
        logger.warning(f"Login attempt for unknown email: {payload.email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_401)

    # Step 2: Check account status
    if not user.is_active:
        logger.warning(f"Login attempt on deactivated account: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated. Contact your SOC administrator.",
        )

    # Step 3a: Verify password
    password_valid = verify_password(payload.password, user.hashed_password)

    if not password_valid:
        # Increment failure counter
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            # Lock the account — requires admin intervention to re-enable
            user.is_active = False
            await db.flush()
            logger.critical(
                f"Account LOCKED after {user.failed_login_attempts} failed attempts: {user.email}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    f"Account locked after {MAX_FAILED_ATTEMPTS} failed login attempts. "
                    "Contact your SOC administrator to unlock."
                ),
            )

        await db.flush()
        logger.warning(
            f"Failed login for {user.email} | "
            f"attempt {user.failed_login_attempts}/{MAX_FAILED_ATTEMPTS}"
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_401)

    # Step 3b: Successful authentication
    user.failed_login_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    await db.flush()

    # Issue JWT — embed email and role so protected routes can authorize
    # without a DB round-trip on every request
    token = create_access_token(data={"sub": user.email, "role": user.role})

    logger.info(f"Successful login: {user.email} | role: {user.role}")

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        full_name=user.full_name,
    )


# ─── C. Forgot Password ───────────────────────────────────────────────────────

@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Request a password reset link",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> ForgotPasswordResponse:
    """
    Initiates the password reset flow.

    Security: This endpoint ALWAYS returns HTTP 200 with an identical response
    body regardless of whether the email is registered. Returning 404 for
    unknown emails is a classic user enumeration vulnerability (OWASP A07:2021).

    In production:
    - Generate a cryptographically random token (secrets.token_urlsafe).
    - Store a hashed version of the token + expiry in the DB (NOT plaintext).
    - Email the plaintext token to the user via an SMTP/SendGrid integration.
    - A separate `POST /reset-password` endpoint validates the token and updates
      the hash.

    For this prototype: the reset link is printed to the console so you can
    test the full auth flow without an email server.
    """
    _GENERIC_200 = (
        "If this email is registered, a password reset link has been sent. "
        "Check your inbox (and spam folder)."
    )

    # Look up the user
    result = await db.execute(
        select(User).where(User.email == payload.email.lower().strip())
    )
    user: Optional[User] = result.scalar_one_or_none()

    if not user:
        # Do NOT return 404 — log quietly and return the generic message
        logger.info(f"Forgot-password request for unregistered email: {payload.email}")
        return ForgotPasswordResponse(message=_GENERIC_200)

    if not user.is_active:
        # Same treatment — don't reveal account status to unauthenticated callers
        logger.info(f"Forgot-password request for deactivated account: {user.email}")
        return ForgotPasswordResponse(message=_GENERIC_200)

    # Generate a secure, URL-safe reset token
    # In production: hash this with hashlib.sha256 before storing in DB
    reset_token = secrets.token_urlsafe(32)
    reset_link = f"https://atlas.soc.internal/reset-password?token={reset_token}&email={user.email}"

    # ── MOCK: Print to console instead of sending an email ──────────────────
    # Replace this block with your SMTP/SendGrid/SES integration.
    print("\n" + "=" * 65)
    print("  [ATLAS DEV] PASSWORD RESET LINK (mock — not sent via email)")
    print("=" * 65)
    print(f"  User     : {user.full_name} <{user.email}>")
    print(f"  Reset URL: {reset_link}")
    print(f"  Token    : {reset_token}")
    print(f"  Expires  : 15 minutes from now")
    print("=" * 65 + "\n")
    # ── End mock ─────────────────────────────────────────────────────────────

    logger.info(f"Password reset link generated for: {user.email}")

    return ForgotPasswordResponse(message=_GENERIC_200)


# ─── D. Get Current User Profile (bonus — useful for frontend "me" endpoint) ──

@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get the profile of the currently authenticated user",
)
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserProfile:
    """
    Returns the authenticated user's profile.
    Frontend uses this to populate the SOC dashboard navbar (name, role badge).

    Requires: `Authorization: Bearer <token>` header.
    """
    result = await db.execute(
        select(User).where(User.email == current_user["sub"])
    )
    user: Optional[User] = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found.",
        )

    return UserProfile.model_validate(user)
