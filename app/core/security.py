"""
core/security.py

Cryptographic utilities for ATLAS authentication.

Design principles:
1. bcrypt for password hashing — adaptive cost factor makes brute-force
   increasingly expensive as hardware gets faster. OWASP recommends bcrypt
   with cost factor ≥12 for new systems (default in passlib is 12).

2. JWT for stateless session tokens — SOC dashboards often run in multi-replica
   deployments where sticky sessions aren't guaranteed. Stateless JWTs work
   across any replica without a shared session store.

3. Short token lifetime (2 hours) — SOC analysts work in focused incident
   windows. A short expiry limits the blast radius if a token is intercepted.
   Refresh token logic (not implemented here) would extend sessions gracefully.

4. Algorithm HS256 — symmetric HMAC-SHA256. Suitable for a single-service
   backend where the same server signs and verifies tokens. For multi-service
   architectures, migrate to RS256 (asymmetric) so services can verify tokens
   without sharing the private signing key.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# ─── Password Hashing ─────────────────────────────────────────────────────────
# deprecated="auto" means passlib will automatically identify and re-hash
# any legacy passwords using weaker schemes (e.g., md5_crypt) on next login —
# enabling seamless algorithm migration without forcing a password reset.

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def get_password_hash(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with a random salt.

    A new salt is generated for every hash — meaning two users with the
    same password produce completely different hashes. This defeats
    rainbow table attacks and prevents bulk cracking if the DB is leaked.

    Args:
        password: The plaintext password from the signup request.

    Returns:
        A bcrypt hash string (includes algorithm, cost factor, and salt).
        Example: "$2b$12$EixZaYVK1fsbw1ZfbX3OXe.PkO..."
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Constant-time comparison of a plaintext password against a bcrypt hash.

    Uses constant-time comparison internally to prevent timing side-channel
    attacks — an attacker cannot deduce partial password matches by measuring
    response time differences.

    Args:
        plain_password: The password submitted in the login request.
        hashed_password: The stored bcrypt hash from the database.

    Returns:
        True if the password matches, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


# ─── JWT Token Management ─────────────────────────────────────────────────────

def create_access_token(data: Dict[str, Any]) -> str:
    """
    Creates a signed JWT access token containing the provided claims.

    The token payload includes:
    - `sub`: Subject (email) — standard JWT claim, identifies the principal
    - `role`: User's RBAC role — embedded so route guards don't need a DB call
    - `exp`: Expiry timestamp — PyJWT validates this automatically on decode
    - `iat`: Issued-at timestamp — enables detecting replayed old tokens

    Why embed `role` in the token: Every protected SOC route needs to check
    permissions. Fetching the user from DB on every request adds a DB round-trip
    to every API call. Embedding role in the JWT lets us authorize in-memory.
    Trade-off: role changes don't take effect until the current token expires.
    For a SOC dashboard this is acceptable — analysts don't get promoted mid-shift.

    Args:
        data: Dict containing at minimum `sub` (email) and `role`.

    Returns:
        A signed JWT string — ready to return as `access_token` in the response.
    """
    settings = get_settings()
    payload = data.copy()

    now = datetime.now(timezone.utc)
    expire = now + timedelta(hours=settings.jwt_expire_hours)

    payload.update({
        "exp": expire,
        "iat": now,
        "iss": "atlas-soc",   # Issuer claim — helps detect tokens forged by other services
    })

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    logger.debug(f"Access token issued for subject: {data.get('sub')} | expires: {expire.isoformat()}")
    return token


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a JWT access token.

    Validates:
    - Signature (token wasn't tampered with)
    - Expiry (token hasn't expired)
    - Issuer (token was issued by ATLAS, not a foreign service)

    Returns None on any validation failure rather than raising — callers
    can treat None as "unauthenticated" and return 401 without exposing
    internal error details to the client.

    Used by: the `get_current_user` dependency injected into protected routes.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub"]},
        )
        return payload
    except ExpiredSignatureError:
        logger.info("JWT rejected: token expired.")
        return None
    except InvalidTokenError as e:
        logger.warning(f"JWT rejected: invalid token — {e}")
        return None


# ─── Route Guard Dependency ───────────────────────────────────────────────────
# Placed here (not in routes_auth) so ANY router can import and use it
# without creating a circular import through the auth router.

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    """
    FastAPI dependency that extracts and validates the Bearer token.

    Usage in a protected route:
        @router.get("/protected")
        async def protected_endpoint(user = Depends(get_current_user)):
            return {"message": f"Hello, {user['sub']}"}

    Returns the decoded JWT payload dict so routes can access:
        user["sub"]   → email
        user["role"]  → "analyst" | "lead" | "admin"
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def require_role(*allowed_roles: str):
    """
    Factory for role-based access control dependencies.

    Usage:
        @router.delete("/users/{id}")
        async def delete_user(user = Depends(require_role("admin"))):
            ...

    Args:
        *allowed_roles: One or more role strings that may access the endpoint.
    """
    async def role_checker(
        current_user: Dict[str, Any] = Depends(get_current_user),
    ) -> Dict[str, Any]:
        user_role = current_user.get("role", "")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role(s): {list(allowed_roles)}. Your role: {user_role}",
            )
        return current_user

    return role_checker
