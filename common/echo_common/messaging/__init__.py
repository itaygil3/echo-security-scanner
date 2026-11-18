"""RabbitMQ messages and queue declarations shared by the scheduler and the scanner workers."""

from echo_common.messaging.queues import dead_letter_queue_name, declare_scan_queue
from echo_common.messaging.scan_request import ScanRequest

__all__ = ["ScanRequest", "dead_letter_queue_name", "declare_scan_queue"]
