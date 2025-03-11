"""
Kafka Configuration Module.

This module provides configuration for connecting to a Kafka cluster.
It defines the KafkaProducerConfig class, which encapsulates connection parameters such as
bootstrap servers, number of retries, and acknowledgment settings (acks) used in Kafka Producer.
"""
from typing import Union, Optional


class KafkaProducerConfig:
    """KafkaProducerConfig encapsulates the configuration settings required to establish
    a connection to a Kafka cluster."""

    def __init__(
            self,
            bootstrap_servers: str,
            retries: int,
            acks: Union[int, str],
            linger_ms: int,
            batch_size: int,
            health_check_interval: int,
            compression_type: Optional[str] = None,
    ):
        """Initialize a new instance of KafkaProducerConfig with the specified parameters.

        Args:
            bootstrap_servers (str): A comma-separated string specifying the Kafka broker addresses.
            retries (int, optional): The number of retry attempts when sending messages.
            acks (Union[int, str], optional): The acknowledgment policy to ensure message
            durability.
            linger_ms (int, optional): The number of milliseconds to buffer data before sending
            a batch. This can help improve throughput at the expense of latency.
            batch_size (int, optional): The size (in bytes) of the batch of messages to be sent.
            Larger values may increase throughput.
            health_check_interval (int, optional): The interval, in seconds, to perform connection
            health checks.
            compression_type (Optional[str], optional): The compression algorithm for the messages.
                Options include None, 'gzip', 'snappy', 'lz4', or 'zstd'. Defaults to None.
        """
        self.bootstrap_servers = bootstrap_servers
        self.retries = retries
        self.acks = acks
        self.linger_ms = linger_ms
        self.batch_size = batch_size
        self.compression_type = compression_type
        self.health_check_interval = health_check_interval
