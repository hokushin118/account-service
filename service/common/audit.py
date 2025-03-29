"""
Audit Utilities Module

This module implements audit logging functionality for a Flask application.
It leverages Kafka to asynchronously log audit messages that capture details
of incoming requests and outgoing responses.
"""
import logging
import os
from datetime import datetime
from functools import wraps
from json import JSONDecodeError
from typing import Any, Union, Optional, Callable

from flask import request, Response
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from kafka.producer.future import RecordMetadata  # pylint: disable=E0401

from service.common.env_utils import get_int_from_env
from service.configs import KafkaProducerConfig
from service.kafka.kafka_producer import (
    KafkaProducerManager,
    generate_correlation_id
)

logger = logging.getLogger(__name__)

# Default username if JWT identity is missing
ANONYMOUS_USER = 'Anonymous'

# Kafka Configuration
KAFKA_BOOTSTRAP_SERVERS = os.environ.get(
    'KAFKA_AUDIT_BOOTSTRAP_SERVERS',
    'kafka:9093'
)
KAFKA_TOPIC = os.environ.get(
    'KAFKA_AUDIT_TOPIC',
    'audit-events'
)
KAFKA_RETRIES = get_int_from_env(
    'KAFKA_AUDIT_RETRIES',
    5
)
KAFKA_ACKS = get_int_from_env(
    'KAFKA_AUDIT_ACKS',
    1
)
KAFKA_LINGER_MS = get_int_from_env(
    'KAFKA_AUDIT_LINGER_MS',
    100
)
KAFKA_BATCH_SIZE = get_int_from_env(
    'KAFKA_AUDIT_BATCH_SIZE',
    16384
)
KAFKA_COMPRESSION = os.environ.get(
    'KAFKA_AUDIT_COMPRESSION',
    'gzip'
)
KAFKA_HEALTH_CHECK_INTERVAL = get_int_from_env(
    'KAFKA_AUDIT_HEALTH_CHECK_INTERVAL',
    60
)


class AuditLogger:
    """Manages Kafka-based audit logging for a Flask application."""

    def __init__(self):
        """Initializes the AuditLogger with Kafka producer configuration."""
        # Create the Kafka producer configuration
        self.config = KafkaProducerConfig(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            retries=KAFKA_RETRIES,
            acks=KAFKA_ACKS,
            linger_ms=KAFKA_LINGER_MS,
            batch_size=KAFKA_BATCH_SIZE,
            compression_type=KAFKA_COMPRESSION,
            health_check_interval=KAFKA_HEALTH_CHECK_INTERVAL,
        )
        # Instantiate the Kafka producer manager.
        self.producer_manager = KafkaProducerManager(
            config=self.config
        )

    def get_producer_manager(self) -> KafkaProducerManager:
        """Returns the KafkaProducerManager instance."""
        return self.producer_manager

    @staticmethod
    def get_request_body_or_none() -> Union[Any, None]:
        """Retrieves the request body from a Flask request, handling both JSON and
        non-JSON data.

        Returns:
            The request body (dict for JSON, str for other types), or None if the
            request body is empty.
        """
        if not request.data:
            return None

        if request.is_json:
            try:
                request_body = request.get_json()
                return request_body or None
            except JSONDecodeError as err:
                logger.error(
                    "Failed to decode JSON. Error: %s",
                    err
                )
                return None
            except Exception as err:  # pylint: disable=W0703
                logger.error(
                    "Unexpected error during JSON processing: %s",
                    err
                )
                return None

        # For non-JSON requests, return text data
        request_body = request.get_data(as_text=True)
        return request_body if request_body else None

    @staticmethod
    def on_send_success(record_metadata: RecordMetadata, key: bytes) -> None:
        """Callback function executed upon successful Kafka message delivery.

        This function is intended to serve as the success callback for KafkaProducer.send().
        It logs details about the sent message, including the Kafka topic, message key,
        partition, and offset.

        Args:
            record_metadata (RecordMetadata): Contains metadata about the sent message,
                including:
                    - topic: The Kafka topic where the message was published.
                    - key: The message key associated with the sent message.
                    - partition: The partition to which the message was written.
                    - offset: The offset of the message in the partition.
            key (bytes): The message key associated with the sent message.
        """
        logger.info(
            "Kafka message sent successfully. Topic: %s, Key: %s, Partition: %s, "
            "Offset: %s",
            record_metadata.topic,
            key,
            record_metadata.partition,
            record_metadata.offset,
        )

    @staticmethod
    def on_send_error(kafka_err: Exception) -> None:
        """Callback function for a failed Kafka message send.

         This function is intended to be used as an error callback when
         sending messages via KafkaProducer.
         It logs the exception encountered during the send operation.

         Args:
             kafka_err (Exception): The exception raised during the
             Kafka message send process.
         """
        logger.error(
            "Error occurred during Kafka send: %s",
            kafka_err
        )

    def audit_log_kafka(
            self,
            function: Callable
    ) -> Callable:
        """Decorator for audit logging using Kafka. This decorator intercepts a Flask route's
        request and response, logs the necessary details (including request headers, body, response,
        and client information), and sends an audit message to Kafka.

        Args:
            function (Callable): The Flask route function to be decorated.

        Returns:
            The decorated function.

        Note:
            This decorator requires that a valid Kafka producer (KAFKA_PRODUCER) is initialized
            and that a valid JWT token is present in the incoming request. The current user will
            default to ANONYMOUS_USER if get_jwt_identity() returns None.
        """

        @wraps(function)
        def wrapper(*args, **kwargs) -> Response:
            correlation_id = generate_correlation_id()
            logger.debug('Correlation ID: %s', correlation_id)

            try:
                # Verify the JWT token and get the current user identity.
                verify_jwt_in_request()
                current_user_id: Optional[
                    str] = get_jwt_identity() or ANONYMOUS_USER
                logger.debug("Current user ID: %s", current_user_id)

                # Prepare headers without sensitive authorization information
                request_headers = dict(request.headers)
                request_headers.pop(
                    'Authorization',
                    None
                )
                logger.debug("Request headers: %s", request_headers)

                # Get request body.
                request_body = self.get_request_body_or_none()
                logger.debug("Request body: %s", request_body)

                # Process the request by calling the decorated function
                response: Response = function(*args, **kwargs)
                logger.debug("Response: %s", response)

                # Extract the response body
                response_body = (
                    response.get_json() if response.is_json else response.get_data(
                        as_text=True
                    )
                )
                logger.debug("Response body: %s", response_body)

                # Extract the response method
                request_method = request.method
                logger.debug("Request method: %s", request_method)

                # Build audit log entry
                audit_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'user_id': current_user_id,
                    'method': request.method,
                    'url': request.url,
                    'request_headers': request_headers,
                    'request_body': request_body,
                    'response_status': response.status_code,
                    'response_body': response_body,
                    'client_ip': request.remote_addr,
                    'correlation_id': correlation_id,
                }

                # Use the current user as the key (encoded as UTF-8) to help
                # with ordered partitioning
                key_value = f"{current_user_id}-{request_method}".encode(
                    'utf-8')

                # Create a Kafka producer on-demand, or return the cached producer
                producer = self.producer_manager.get_producer()
                if producer is None:
                    logger.error('Kafka producer is not available.')
                    return response

                # Send audit log to Kafka asynchronously with callbacks
                producer.send(
                    KAFKA_TOPIC,
                    key=key_value,
                    value=audit_data
                ).add_callback(
                    lambda metadata, key=key_value: self.on_send_success(
                        metadata,
                        key
                    )
                ).add_errback(
                    self.on_send_error
                )

                # Ensure message delivery
                # Block until all pending messages are at least put on the network
                producer.flush()
                logger.info("Audit log sent to Kafka: %s", audit_data)
                return response

            except Exception as err:  # pylint: disable=W0703
                logger.error(
                    "Audit logging to Kafka failed (correlation_id: %s): %s",
                    correlation_id,
                    err
                )
                # Return the response regardless of logging failure
                return function(*args, **kwargs)

        wrapper.__name__ = function.__name__
        return wrapper
