"""Backward-compatibility shim for backend.main."""

from zenshield.main import app, create_app

__all__ = ["app", "create_app"]
