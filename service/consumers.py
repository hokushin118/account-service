"""
Kafka Consumer Setup Module.

This module configures and initializes a Kafka consumer using the
KafkaConsumerManager. It provides functions to set up the consumer with
specified configurations and a message handler.
"""
import logging
import os

from cba_core_lib.kafka import KafkaConsumerManager
from cba_core_lib.kafka.configs import (
    KafkaConsumerConfig,
    SecurityProtocol,
    AutoOffsetReset
)
from kafka.consumer.fetcher import ConsumerRecord

logger = logging.getLogger(__name__)

# Kafka Configuration
KAFKA_BOOTSTRAP_SERVERS = os.environ.get(
    'KAFKA_CONSUMER_BOOTSTRAP_SERVERS',
    'kafka:9093'
)
KAFKA_TOPIC = os.environ.get(
    'KAFKA_CONSUMER_TOPIC',
    'account-events.in'
)


def message_handler(message: ConsumerRecord) -> None:
    """Handles incoming Kafka messages.

    This function processes the received Kafka message, logging its details
    and performing any necessary application-specific logic.

    Args:
        message (ConsumerRecord): The Kafka message received.
    """
    logger.info(
        "Received message: topic=%s, partition=%d, offset=%d, key=%s, value=%s",
        message.topic,
        message.partition,
        message.offset,
        message.key,
        message.value
    )
    logger.info('Started processing the received message...')
    try:
        # Add your message processing logic here
        logger.info('Finished processing the received message...')
    except Exception as err:  # pylint: disable=W0703
        logger.error("Error processing message: %s", err, exc_info=True)
        # Handle the error appropriately (e.g., send to dead-letter queue)


def get_kafka_consumer_manager() -> KafkaConsumerManager:
    """Instantiates the KafkaConsumerManager with the appropriate configuration
    and message handler.

    Returns:
        An instance of KafkaConsumerManager.
    """
    # Create the Kafka consumer configuration
    config = KafkaConsumerConfig(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        topic=KAFKA_TOPIC,
        key_format='str',
        message_format='json',
        security_protocol=SecurityProtocol.PLAINTEXT,
        auto_offset_reset=AutoOffsetReset.EARLIEST,
        enable_auto_commit=False,
        auto_commit_interval_ms=1000,
        max_poll_records=100,
        max_poll_interval_ms=300000,
        session_timeout_ms=10000,
        heartbeat_interval_ms=3000,
        service_name='account-service',
    )
    # Instantiate and return the Kafka consumer manager.
    return KafkaConsumerManager(
        config=config,
        key_deserializer=lambda x: x.decode('utf-8'),
        value_deserializer=lambda x: x.decode('utf-8'),
        message_handler=message_handler,
        health_check_interval_seconds=30
    )
