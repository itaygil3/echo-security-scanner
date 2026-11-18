"""Async database access: engine, table definitions and one repository per table."""

from echo_common.db.engine import create_engine

__all__ = ["create_engine"]
