from sqlalchemy import Column, Integer, String, Table, UniqueConstraint

from echo_common.db.tables.metadata import metadata

packages = Table(
    "packages",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False),
    Column("type", String(64), nullable=False, server_default="unknown"),
    UniqueConstraint("name", "type", name="uq_packages_name_type"),
)
