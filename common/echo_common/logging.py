import logging
import sys


def configure_logging(level: str = "INFO", service: str | None = None) -> None:
    """Configure root logging to stdout so `docker compose logs` shows everything."""
    prefix = f"{service}:" if service else ""
    fmt = f"%(asctime)s %(levelname)-8s [{prefix}%(name)s] %(message)s"
    logging.basicConfig(level=level.upper(), format=fmt, stream=sys.stdout, force=True)
    # Quiet chatty third-party loggers.
    for noisy in ("pika", "sqlalchemy.engine", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
