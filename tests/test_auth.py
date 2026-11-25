"""Focused JWT configuration and token-generation tests."""
import pytest

from app.auth import JwtConfigurationError, create_development_token, jwt_configuration


def test_jwt_configuration_rejects_missing_or_short_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDIT_JWT_SIGNING_KEY", raising=False)
    with pytest.raises(JwtConfigurationError):
        jwt_configuration()
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY", "short")
    monkeypatch.setenv("AUDIT_JWT_ISSUER", "issuer")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE", "audience")
    with pytest.raises(JwtConfigurationError):
        jwt_configuration()


def test_development_token_requires_valid_config_and_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY", "test-signing-key-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AUDIT_JWT_ISSUER", "issuer")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE", "audience")
    assert create_development_token("developer", ["auditor"])
    with pytest.raises(ValueError):
        create_development_token("developer", ["invalid"])
