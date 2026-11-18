from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration shared by all services, loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://echo:echo@localhost:5432/echo"
    rabbitmq_url: str = "amqp://echo:echo@localhost:5672/%2F"
    scan_queue: str = "scan_requests"

    scan_interval_seconds: int = Field(default=900, gt=0)

    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, v: str) -> str:
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    return Settings()
