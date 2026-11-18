class ScannerError(Exception):
    """Base class for expected scan failures (the image gets status FAILED, the worker keeps going)."""


class ImageNotFoundError(ScannerError):
    """The image or tag does not exist, or the registry refused to serve it."""


class ScannerTimeoutError(ScannerError):
    """The scan took longer than the configured timeout."""


class ScannerExecutionError(ScannerError):
    """The scanner tool is missing, crashed, or produced unreadable output."""
