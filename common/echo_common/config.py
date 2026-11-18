from functools import lru_cache

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ImageRef(BaseModel):
    """A container image reference split into name and tag."""

    name: str
    tag: str = "latest"

    @classmethod
    def parse(cls, ref: str) -> "ImageRef":
        ref = ref.strip()
        if not ref:
            raise ValueError("empty image reference")
        # Only treat the last ':' as a tag separator if it comes after the last '/'
        # (so registry ports like "localhost:5000/app" are not mistaken for tags).
        name, sep, tag = ref.rpartition(":")
        if not sep or "/" in tag:
            return cls(name=ref)
        return cls(name=name, tag=tag)

    def __str__(self) -> str:
        return f"{self.name}:{self.tag}"


class Settings(BaseSettings):
    """Runtime configuration shared by all services, loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://echo:echo@localhost:5432/echo"
    rabbitmq_url: str = "amqp://echo:echo@localhost:5672/%2F"
    scan_queue: str = "scan_requests"

    scan_interval_seconds: int = Field(default=900, gt=0)
    scanner_type: str = "trivy"

    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, v: str) -> str:
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    return Settings()
