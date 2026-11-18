from sqlalchemy import Column, String, Table, Text

from echo_common.db.tables.metadata import metadata

cves = Table(
    "cves",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("severity", String(16), nullable=False),
    Column("title", Text),
    Column("description", Text),
    Column("primary_url", Text),
    Column("source", String(32), nullable=False),
)
