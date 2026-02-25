"""
db/models.py

SQLAlchemy ORM models for ATLAS's PostgreSQL schema.

Security design decisions baked into the User model:
- `hashed_password`: We NEVER store plaintext passwords. The column name is
  deliberately named `hashed_password` (not `password`) to make it explicit
  at the ORM layer that this field is always a bcrypt hash.
- `failed_login_attempts`: Enables account lockout logic in the auth service.
  Tracking failed attempts is a CIS Control requirement for enterprise systems.
- `is_active`: Soft deactivation — deactivated accounts are rejected at login
  without deleting audit trail data (login history, incident assignments).
- `last_login`: Used for dormant account detection. SOC policy typically locks
  accounts inactive for 90+ days as they're a lateral movement risk.
- `role`: Drives RBAC — SOC tiers (analyst / lead / admin) get different
  dashboard access levels enforced by route dependencies.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    func,
)

from app.db.database import Base


class User(Base):
    """
    ATLAS user account. Maps to the `users` table in PostgreSQL.

    Role values: "analyst" | "lead" | "admin"
    - analyst: Read-only dashboard, can trigger AI investigations
    - lead: analyst + can update/resolve incidents, modify containment rules
    - admin: lead + user management, model retraining, system settings
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    email = Column(
        String(255),
        unique=True,
        index=True,         # Index on email since every login hits this column
        nullable=False,
    )

    full_name = Column(String(255), nullable=False)

    role = Column(
        String(50),
        nullable=False,
        default="analyst",  # Principle of least privilege: new accounts start as analyst
    )

    hashed_password = Column(String(255), nullable=False)

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        comment="Deactivated accounts cannot log in but retain audit history",
    )

    last_login = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Updated on every successful authentication",
    )

    failed_login_attempts = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Reset to 0 on success; used for account lockout policy",
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role} active={self.is_active}>"
