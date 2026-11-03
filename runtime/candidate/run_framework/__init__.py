"""Inert, hash-bound campaign configuration and append-only attempt tracking.

This is orchestration scaffolding only. It never imports configured code,
launches work, calls evaluators, or grants campaign authority.
"""
from .core import Campaign, FrameworkError, load_config

__all__ = ["Campaign", "FrameworkError", "load_config"]
