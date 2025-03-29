"""
Kafka Consumer Manager Module.

This module provides the KafkaConsumerManager class, which simplifies the management
of Kafka consumers within applications. It handles the lifecycle of a KafkaConsumer,
including initialization, message consumption, health monitoring, and graceful shutdown.
"""
import json
import logging
import threading
import time
from types import TracebackType
from typing import Optional, Type, Callable, Any

from kafka import KafkaConsumer
from kafka.consumer.fetcher import ConsumerRecord
from kafka.errors import (
    NoBrokersAvailable,
    NodeNotReadyError,
    KafkaTimeoutError,
    InvalidConfigurationError,
    UnsupportedVersionError,
    KafkaConnectionError,
)
from kafka.structs import TopicPartition, OffsetAndMetadata

from service.configs import KafkaConsumerConfig

logger = logging.getLogger(__name__)


class KafkaConsumerManager:
    """Manages the Kafka consumer instance.

    This class initializes and maintains a KafkaConsumer instance,
    monitors its health periodically, and can reinitialize it if necessary.
    It is usable both as a context manager and as a stand-alone manager.
    """

    def __init__(
            self,
            config: KafkaConsumerConfig,
            message_handler: Callable[[Any], None]
    ) -> None:
        """Initializes the KafkaConsumerManager with the provided configuration
        and message handler.

        Args:
            config (KafkaConsumerConfig): Kafka consumer configuration.
            message_handler (Callable[[Any], None]): A callable that will be invoked
            with each consumed message.
        """
        self._validate_config(config)
        self.config = config
        self.health_check_interval = self._get_health_check_interval(
            self.config.max_poll_interval_ms
        )
        self.message_handler = message_handler

        self._consumer: Optional[KafkaConsumer] = None
        self._consumer_lock = threading.Lock()

        # Use an event flag to signal threads for a graceful shutdown
        self._stop_event = threading.Event()

        # Start asynchronous Kafka consumer initialization in a background thread.
        # This prevents the __init__ method from blocking, as consumer initialization can be
        # time-consuming,particularly with slow brokers or network latency
        self._start_async_init()

        # Start health check thread right away
        self._start_health_check_thread()

        if self._consumer:
            self._consume_messages()
        else:
            logger.error(
                'Kafka consumer failed to start during initialization.'
            )

    def __enter__(self) -> "KafkaConsumerManager":
        """Allows KafkaConsumerManager to be used as a context manager."""
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException],
            traceback: Optional[TracebackType]
    ) -> None:
        """Closes the KafkaConsumer when exiting the context manager to ensure
        proper resource cleanup.

        Args:
            exc_type (Optional[Type[BaseException]]): The type of the exception that caused
            the context manager to exit, or None if no exception occurred.
            exc_value (Optional[BaseException]): The exception instance that caused the context
            manager to exit, or None if no exception occurred.
            traceback (Optional[TracebackType]): The traceback object associated with the exception,
                or None if no exception occurred.

        This method is automatically called upon exiting the context and delegates
        the task of releasing any established connections by invoking the
        close_consumer() method.
        """
        self.close_consumer()
        self._stop_event.set()

    def get_consumer(self) -> Optional[KafkaConsumer]:
        """Get (and lazily create) a KafkaConsumer instance.

        It creates a new KafkaConsumer if not already initialized and return it.
        In case of initialization failures, it should log the error and return None.

        Returns:
            Optional[KafkaConsumer]: The initialized KafkaConsumer or None if instantiation failed.
        """
        if self._consumer is None:
            with self._consumer_lock:
                if self._consumer is None:  # double check locking
                    logger.warning(
                        'Kafka consumer has not been initialized yet. Trying to initialize now.'
                    )
                    self._async_init()
                    if self._consumer is None:
                        logger.error(
                            'Consumer is still None after sync attempt. returning None'
                        )
                        return None
        return self._consumer

    def close_consumer(self) -> None:
        """Closes the Kafka consumer if it's initialized.

        It should safely close the consumer connection and unset the instance variable.
        After closure, it logs that the consumer has been closed.
        """
        with self._consumer_lock:
            if self._consumer:
                try:
                    self._consumer.close()
                    logger.info('Kafka consumer closed successfully.')
                except Exception as err:  # pylint: disable=W0703
                    logger.exception(
                        'Error while closing Kafka consumer: %s',
                        err
                    )
                finally:
                    logger.info('Kafka consumer closed.')
                    self._consumer = None
            else:
                logger.info(
                    'Close consumer called, consumer was already none.'
                )

    def is_consumer_healthy(self) -> bool:
        """Check if the Kafka consumer is healthy.

        Returns:
            bool: True if the consumer is initialized and able to
            communicate with the Kafka cluster; False otherwise.
        """
        if self._consumer is None:
            return False
        try:
            # Requesting topics is a light-weight operation to check health.
            _ = self._consumer.topics()
            # pylint: disable=R0801
            return True
        except (
                KafkaConnectionError,
                KafkaTimeoutError
        ) as err:
            logger.warning(
                "Kafka consumer health check failed: %s",
                err
            )
            return False
        except Exception as err:  # pylint: disable=W0703
            logger.exception(
                "Unexpected error during consumer health check: %s",
                err
            )
            return False

    def commit_message(self, message: ConsumerRecord) -> None:
        """Manually commits the offset of a consumed message.
        Note: This only works if auto commit is disabled.
        """
        if self._consumer:
            # Create a TopicPartition and commit offsets using OffsetAndMetadata.
            topic_partition = TopicPartition(message.topic, message.partition)
            offsets = {
                topic_partition: OffsetAndMetadata(message.offset + 1, None)
            }
            self._consumer.commit(offsets=offsets)
            logger.info(
                "Committed offset %s for partition %s",
                message.offset + 1,
                message.partition
            )

    def _start_async_init(self) -> None:
        """Start an asynchronous thread to initialize the Kafka consumer.

        This method creates a new daemon thread that targets the _async_init method, which
        attempts to lazily initialize the Kafka consumer instance. Since the thread is marked
        as a daemon, it will not prevent the application from exiting if it is still running.
        """
        threading.Thread(
            target=self._async_init,
            daemon=True
        ).start()

    def _async_init(self) -> None:
        """Initializes the Kafka consumer in a thread-safe way.

        This method sets up the consumer using the given configuration and
        deserializers. The consumer is stored if initialization succeeds.
        """
        with self._consumer_lock:
            if self._consumer is None:
                try:
                    consumer_kwargs = {
                        'bootstrap_servers': self.config.bootstrap_servers,
                        'auto_offset_reset': self.config.auto_offset_reset.value,
                        'enable_auto_commit': self.config.enable_auto_commit,
                        'group_id': self.config.group_id,
                        'security_protocol': self.config.security_protocol.value,
                        'key_deserializer': self._get_deserializer(
                            self.config.key_format
                        ),
                        'value_deserializer': self._get_deserializer(
                            self.config.message_format
                        ),
                    }

                    if self.config.session_timeout_ms is not None:
                        consumer_kwargs[
                            'session_timeout_ms'
                        ] = self.config.session_timeout_ms

                    if self.config.heartbeat_interval_ms is not None:
                        consumer_kwargs[
                            'heartbeat_interval_ms'
                        ] = self.config.heartbeat_interval_ms

                    if self.config.max_poll_interval_ms is not None:
                        consumer_kwargs[
                            'max_poll_interval_ms'
                        ] = self.config.max_poll_interval_ms

                    if self.config.max_poll_interval_ms is not None:
                        consumer_kwargs[
                            'max_poll_interval_ms'
                        ] = self.config.max_poll_interval_ms

                    if self.config.retry_attempts is not None:
                        consumer_kwargs[
                            'retry_attempts'
                        ] = self.config.retry_attempts

                    if self.config.retry_delay_ms is not None:
                        consumer_kwargs[
                            'retry_delay_ms'
                        ] = self.config.retry_delay_ms

                    if self.config.consumer_id is not None:
                        consumer_kwargs[
                            'consumer_id'
                        ] = self.config.consumer_id

                    self._consumer = KafkaConsumer(
                        self.config.topic,
                        **consumer_kwargs
                    )
                    logger.info(
                        "Kafka consumer initialized asynchronously "
                        "with bootstrap servers: %s, auto_offset_reset: %s, "
                        "enable auto commit: %s, topic: %s, group_id: %s",
                        self.config.bootstrap_servers,
                        self.config.auto_offset_reset,
                        self.config.enable_auto_commit,
                        self.config.topic,
                        self.config.group_id,
                    )
                # pylint: disable=R0801
                except (
                        NoBrokersAvailable,
                        NodeNotReadyError,
                        KafkaTimeoutError,
                        InvalidConfigurationError,
                        UnsupportedVersionError,
                ) as err:
                    logger.error(
                        "Failed to initialize Kafka consumer: %s",
                        err
                    )
                    self._consumer = None
                except Exception as err:  # pylint: disable=W0703
                    logger.exception(
                        "Unexpected error during consumer initialization: %s",
                        err
                    )
                    self._consumer = None

    def _reinitialize_consumer(self) -> None:
        """Reinitializes the Kafka consumer.

        This method closes any existing consumer, attempts to initialize a new one,
        and restarts message consumption if successful.
        """
        logger.warning('Reinitializing Kafka consumer...')
        self.close_consumer()
        self._async_init()
        if self._consumer:
            logger.info(
                'Kafka consumer reinitialized successfully...'
            )
            self._consume_messages()
        else:  # pylint: disable=R0801
            logger.error(
                'Failed to reinitialize Kafka consumer...'
            )

    def _start_health_check_thread(self) -> None:  # pylint: disable=R0801
        """Start the background health check thread.

        The thread runs as a daemon and periodically checks the Kafka
        consumer's health by invoking _health_check_loop."""
        # pylint: disable=R0801
        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True
        )
        self._health_check_thread.start()

    def _health_check_loop(self) -> None:
        """Periodically verify the Kafka consumer's health.

        This loop runs indefinitely, checking the health at intervals specified by
        health_check_interval. If the consumer is found to be unhealthy,
        it attempts reinitialization.
        """
        while not self._stop_event.is_set():
            if not self.is_consumer_healthy():
                self._reinitialize_consumer()
            time.sleep(self.health_check_interval)

    def _consume_messages(self) -> None:
        """Consumes messages from Kafka in a separate daemon thread."""

        def consume_loop() -> None:
            while not self._stop_event.is_set():
                try:
                    with self._consumer_lock:
                        if self._consumer is None:
                            logger.error(
                                'Kafka consumer is None. Exiting consumption loop.'
                            )
                            return
                        records = self._consumer.poll(timeout_ms=1000)
                    if records:
                        for _, messages in records.items():
                            for message in messages:
                                logger.debug(
                                    "Message received: %s",
                                    message.value
                                )
                                self.message_handler(message)
                                if not self.config.enable_auto_commit:
                                    logger.debug(
                                        'Manual commit: committing message offset...'
                                    )
                                    self.commit_message(message)
                except Exception as err:  # pylint: disable=W0703
                    logger.error(
                        "Error during message consumption: %s",
                        err,
                        exc_info=True
                    )
                    break

            with self._consumer_lock:
                if self._consumer:
                    self.close_consumer()

        thread = threading.Thread(target=consume_loop, daemon=True)
        thread.start()

    @staticmethod
    def _validate_config(config: KafkaConsumerConfig) -> None:
        """Validates the essential configuration parameters of a KafkaConsumerConfig object.

        This method checks for the presence of required configurations such as
        'bootstrap_servers', 'topic', and 'group_id'. If any of these are missing,
        it raises a ValueError with a descriptive message.

        Args:
            config (KafkaConsumerConfig): The configuration object to validate.

        Raises:
            ValueError: If any of the required configurations are None.
        """
        if config.bootstrap_servers is None:
            raise ValueError('bootstrap_servers must be provided.')
        if config.topic is None:
            raise ValueError('topic must be provided.')
        if config.group_id is None:
            raise ValueError('group_id must be provided.')

    @staticmethod
    def _get_health_check_interval(max_poll_interval_ms: int) -> int:
        """Calculates the health check interval in seconds based on the max poll interval.

        If the provided max_poll_interval_ms is None, a default hardcoded value is used.
        A warning is logged in this case to indicate the use of the default value.

        Args:
            max_poll_interval_ms (int): The maximum interval in milliseconds that the consumer
                                         can be idle before being considered dead.

        Returns:
            int: The health check interval in seconds.
        """
        if max_poll_interval_ms is None:
            max_poll_interval_ms = 300000  # 5 minutes in milliseconds
            logger.warning(
                "max_poll_interval_ms is None. Using hardcoded max poll interval: %s ms",
                max_poll_interval_ms,
            )
        return int(max_poll_interval_ms / 1000)

    @staticmethod
    def _get_deserializer(format_type: str) -> Optional[Callable[[Any], Any]]:
        """Returns an appropriate deserializer function based on the provided format type.

        Args:
            format_type: A string indicating the expected format ('json' or 'str').

        Returns:
            A function that deserializes the byte input, or None if the format is unsupported.
        """
        if format_type == 'json':
            return lambda x: json.loads(x.decode('utf-8')) if x else None
        if format_type == 'str':
            return lambda x: x.decode('utf-8') if x else None
        return None
