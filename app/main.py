"""Supported runtime entry point for the secure tenant-aware V4 application."""

from app.v4_main import app, create_v4_app

__all__ = ["app", "create_v4_app"]
