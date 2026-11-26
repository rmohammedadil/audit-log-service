"""JWT authentication and role checks for the trusted prototype API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
import re
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


JWT_ALGORITHM = "HS256"
ALLOWED_ROLES = frozenset({"writer", "auditor", "regulator", "admin"})
_TENANT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
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


@dataclass(frozen=True)
class TenantAuthenticatedIdentity:
    """V4 identity with a verified tenant claim; not used by legacy routes."""

    subject: str
    tenant_id: str
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


def validate_tenant_id(value: object) -> str:
    """Accept only one canonical tenant identifier; no fallback exists."""

    if type(value) is not str or _TENANT_ID.fullmatch(value) is None:
        raise ValueError("invalid tenant claim")
    return value


def _validated_claims(
    credentials: HTTPAuthorizationCredentials | None,
) -> tuple[str, frozenset[str], dict[str, object]]:
    """Decode common JWT claims before legacy or V4 identity construction."""

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
        return subject, role_set, claims
    except (jwt.PyJWTError, JwtConfigurationError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token") from None


def authenticate(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> AuthenticatedIdentity:
    """Validate legacy role-only JWTs for the existing V3 route boundary."""

    subject, roles, _ = _validated_claims(credentials)
    return AuthenticatedIdentity(subject, roles)


def authenticate_v4(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> TenantAuthenticatedIdentity:
    """Validate V4 JWTs and reject every token without a valid tenant claim."""

    subject, roles, claims = _validated_claims(credentials)
    try:
        return TenantAuthenticatedIdentity(subject, validate_tenant_id(claims.get("tenant_id")), roles)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token") from None


def require_roles(*permitted_roles: str) -> Callable[[AuthenticatedIdentity], AuthenticatedIdentity]:
    """Create a dependency that checks roles after cryptographic validation."""

    def authorize(identity: AuthenticatedIdentity = Depends(authenticate)) -> AuthenticatedIdentity:
        if not identity.roles.intersection(permitted_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return identity

    return authorize


def require_v4_roles(
    *permitted_roles: str,
) -> Callable[[TenantAuthenticatedIdentity], TenantAuthenticatedIdentity]:
    """Role gate for future V4 routes; it never accepts a legacy identity."""

    def authorize(
        identity: TenantAuthenticatedIdentity = Depends(authenticate_v4),
    ) -> TenantAuthenticatedIdentity:
        if not identity.roles.intersection(permitted_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return identity

    return authorize


def create_development_token(
    subject: str,
    roles: list[str],
    expires_minutes: int = 60,
    *,
    tenant_id: str | None = None,
) -> str:
    """Create a locally signed test token; no HTTP issuance endpoint exists."""

    config = jwt_configuration()
    if not subject.strip() or not roles or set(roles) - ALLOWED_ROLES:
        raise ValueError("subject and roles are invalid")
    if tenant_id is not None:
        tenant_id = validate_tenant_id(tenant_id)
    now = datetime.now(timezone.utc)
    claims: dict[str, object] = {
        "sub": subject, "roles": roles, "iss": config.issuer,
        "aud": config.audience, "iat": now, "exp": now + timedelta(minutes=expires_minutes),
    }
    if tenant_id is not None:
        claims["tenant_id"] = tenant_id
    return jwt.encode(claims, config.signing_key, algorithm=JWT_ALGORITHM)
