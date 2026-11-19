from sqlalchemy import Column, DateTime, ForeignKey, Integer, SmallInteger, String, Table, UniqueConstraint, func

from echo_common.db.tables.metadata import metadata

image_cves = Table(
    "image_cves",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("image_id", Integer, ForeignKey("images.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("cve_id", String(64), ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("package_id", Integer, ForeignKey("packages.id", ondelete="CASCADE"), nullable=False),
    Column("installed_version", String(255), nullable=False),
    Column("fixed_version", String(255)),
    Column("severity", SmallInteger, nullable=False, index=True),  # Severity IntEnum value
    Column("detected_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint("image_id", "cve_id", "package_id", "installed_version", name="uq_image_cve_package"),
)
