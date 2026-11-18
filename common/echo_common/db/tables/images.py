from sqlalchemy import Column, DateTime, Integer, String, Table, Text, UniqueConstraint, func

from echo_common.db.tables.metadata import metadata

images = Table(
    "images",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False),
    Column("tag", String(128), nullable=False),
    Column("last_scan_at", DateTime(timezone=True)),
    Column("scan_status", String(16), nullable=False, server_default="PENDING"),
    Column("last_error", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint("name", "tag", name="uq_images_name_tag"),
)
