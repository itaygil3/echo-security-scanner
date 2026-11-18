from aio_pika.abc import AbstractChannel, AbstractQueue


def dead_letter_queue_name(queue_name: str) -> str:
    """Queue receiving messages rejected from `queue_name`."""
    return f"{queue_name}.dlq"


async def declare_scan_queue(channel: AbstractChannel, queue_name: str) -> AbstractQueue:
    """Declare (create if missing) the durable scan queue and its dead-letter queue (DLQ).

    Rejected messages go straight to the DLQ through RabbitMQ's default exchange (""), which routes
    by queue name, so no extra exchange is needed.
    Publisher and consumers both call this so the queue always exists with the same arguments
    (RabbitMQ refuses re-declaring a queue with different ones).
    """
    dlq_name = dead_letter_queue_name(queue_name)
    await channel.declare_queue(dlq_name, durable=True)
    return await channel.declare_queue(
        queue_name,
        durable=True,
        arguments={"x-dead-letter-exchange": "", "x-dead-letter-routing-key": dlq_name},
    )
