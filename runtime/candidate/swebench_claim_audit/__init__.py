"""Prospective, evidence-bound SWE-bench claim audit adapter."""

from .adapter import audit_instance, validate_zip_archive
from .engine_bridge import bind_to_context_engine

__all__ = ["audit_instance", "bind_to_context_engine", "validate_zip_archive"]
