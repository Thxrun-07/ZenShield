"""Backward-compatibility shim for backend.config."""

from zenshield.core.config import Settings, get_settings, settings

__all__ = ["Settings", "get_settings", "settings"]
