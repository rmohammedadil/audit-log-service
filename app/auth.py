"""JWT authentication and role checks for the trusted prototype API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


JWT_ALGORITHM = "HS256"
ALLOWED_ROLES = frozenset({"writer", "auditor", "regulator", "admin"})
bearer_scheme = HTTPBearer(auto_error=False)


class JwtConfigurationError(ValueError):
    """Raised at startup for missing or unsafe local signing configuration."""


@dataclass(frozen=True)
class JwtConfiguration:
    signing_key: str
    issuer: str
    audience: str


@dataclass(frozen=True)
class AuthenticatedIdentity:
    subject: str
    roles: frozenset[str]


def jwt_configuration() -> JwtConfiguration:
    """Read explicit configuration; a short/shared default is never accepted."""

    key = os.environ.get("AUDIT_JWT_SIGNING_KEY")
    issuer = os.environ.get("AUDIT_JWT_ISSUER")
    audience = os.environ.get("AUDIT_JWT_AUDIENCE")
    if key is None or len(key.strip()) < 32:
        raise JwtConfigurationError("AUDIT_JWT_SIGNING_KEY must be at least 32 characters")
    if not issuer or not issuer.strip() or not audience or not audience.strip():
        raise JwtConfigurationError("AUDIT_JWT_ISSUER and AUDIT_JWT_AUDIENCE are required")
    return JwtConfiguration(key, issuer, audience)


def authenticate(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> AuthenticatedIdentity:
    """Validate a single explicitly configured HS256 bearer token."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        config = jwt_configuration()
        claims = jwt.decode(
            credentials.credentials,
            config.signing_key,
            algorithms=[JWT_ALGORITHM],
            issuer=config.issuer,
            audience=config.audience,
            options={"require": ["exp", "sub", "iss", "aud"]},
        )
        subject = claims["sub"]
        roles = claims.get("roles")
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("invalid subject")
        if not isinstance(roles, list) or not roles or any(type(role) is not str for role in roles):
            raise ValueError("invalid roles")
        role_set = frozenset(roles)
        if len(role_set) != len(roles) or not role_set <= ALLOWED_ROLES:
            raise ValueError("invalid roles")
        return AuthenticatedIdentity(subject, role_set)
    except (jwt.PyJWTError, JwtConfigurationError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token") from None


def require_roles(*permitted_roles: str) -> Callable[[AuthenticatedIdentity], AuthenticatedIdentity]:
    """Create a dependency that checks roles after cryptographic validation."""

    def authorize(identity: AuthenticatedIdentity = Depends(authenticate)) -> AuthenticatedIdentity:
        if not identity.roles.intersection(permitted_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return identity

    return authorize


def create_development_token(subject: str, roles: list[str], expires_minutes: int = 60) -> str:
    """Create a locally signed test token; no HTTP issuance endpoint exists."""

    config = jwt_configuration()
    if not subject.strip() or not roles or set(roles) - ALLOWED_ROLES:
        raise ValueError("subject and roles are invalid")
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": subject, "roles": roles, "iss": config.issuer,
                       "aud": config.audience, "iat": now, "exp": now + timedelta(minutes=expires_minutes)},
                      config.signing_key, algorithm=JWT_ALGORITHM)
