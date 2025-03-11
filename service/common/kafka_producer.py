"""
Kafka Producer Management Module.

This module provides the KafkaProducerManager class that encapsulates the logic
for lazy initialization, retrieval, and proper closure of a KafkaProducer
instance. It allows message sending to Kafka with configurable retries and
handles any errors that may occur during initialization, such as broker unavailability,
network issues, or misconfigurations. The module leverages Python's logging
module to capture and log the relevant information and errors.
"""
import json
import logging
import threading
import time
from types import TracebackType
from typing import Optional, Union, Type

from kafka import KafkaProducer  # pylint: disable=E0401
from kafka.errors import (  # pylint: disable=E0401
    NoBrokersAvailable,
    NodeNotReadyError,
    KafkaTimeoutError,
    InvalidConfigurationError,
    UnsupportedVersionError,
    KafkaConnectionError,
)

from service.configs.kafka_config import KafkaProducerConfig

logger = logging.getLogger(__name__)


class KafkaProducerManager:
    """
    Manages the Kafka producer instance.

    It should encapsulate the logic for lazy initialization,
    retrieval, and proper closure of a KafkaProducer used for sending messages.
    """
    # The __consumer_offsets is an internal Kafka topic that stores the offsets
    # of consumer group. Kafka automatically creates this topic when the
    # first consumer group commits an offset
    CONSUMER_OFFSETS_TOPIC = '__consumer_offsets'

    def __init__(
            self,
            config: KafkaProducerConfig
    ):
        """Initializes the KafkaProducerManager with the given bootstrap servers and retry count.

        It should store the configuration parameters and prepare the manager
        for lazy creation of the producer instance.

        Args:
            config (KafkaProducerConfig): Kafka configuration
        """
        self.bootstrap_servers = config.bootstrap_servers
        self.retries = self._validate_non_negative(config.retries)
        self.acks = self._validate_acks(config.acks)
        self.linger_ms = self._validate_non_negative(config.linger_ms)
        self.batch_size = self._validate_non_negative(config.batch_size)
        self.compression_type = config.compression_type
        self.health_check_interval = config.health_check_interval

        self._producer: Optional[KafkaProducer] = None
        self._producer_lock = threading.Lock()

        self._start_async_init()
        self._start_health_check_thread()

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException],
            traceback: Optional[TracebackType]
    ) -> None:
        """Closes the KafkaProducer when exiting the context manager to ensure
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
        close_producer() method.
        """
        self.close_producer()

    def get_producer(self) -> Optional[KafkaProducer]:
        """Get (and lazily create) a KafkaProducer instance.

        It creates a new KafkaProducer if not already initialized and return it.
        In case of initialization failures, it should log the error and return None.

        Returns:
            Optional[KafkaProducer]: The initialized KafkaProducer or None if instantiation failed.
        """
        if self._producer is None:
            with self._producer_lock:
                if self._producer is None:  # double check locking.
                    logger.warning(
                        'Kafka producer has not been initialized yet. Trying to initialize now.'
                    )
                    self._async_init()
                    if self._producer is None:
                        logger.error(
                            'Producer is still None after sync attempt. returning None'
                        )
                        return None
        return self._producer

    def close_producer(self):
        """Closes the Kafka producer if it's initialized.

        It should safely close the producer connection and unset the instance variable.
        After closure, it logs that the producer has been closed.
        """
        if self._producer:
            self._producer.close()
            self._producer = None
            logger.info('Kafka producer closed...')

    def is_producer_healthy(self) -> bool:
        """Check if the Kafka producer is healthy.

        Returns:
            bool: True if the producer is initialized and able to
            communicate with the Kafka cluster; False otherwise.
        """
        if self._producer is None:
            return False
        try:
            # Validate health by checking connectivity using a known internal topic
            self._producer.partitions_for(
                self.CONSUMER_OFFSETS_TOPIC
            )
            return True
        except (
                KafkaConnectionError,
                KafkaTimeoutError
        ) as err:
            logger.warning(
                "Kafka producer health check failed: {%s}", err
            )
            return False
        except Exception as err:  # pylint: disable=W0703
            logger.exception(
                "Unexpected error during health check: {%s}", err
            )
            return False

    def _start_async_init(self) -> None:
        """Start an asynchronous thread to initialize the Kafka producer.

        This method creates a new daemon thread that targets the _async_init method, which
        attempts to lazily initialize the Kafka producer instance. Since the thread is marked
        as a daemon, it will not prevent the application from exiting if it is still running.
        """
        threading.Thread(
            target=self._async_init,
            daemon=True
        ).start()

    def _async_init(self) -> None:
        """Asynchronously initialize the Kafka producer.

        This method acquires a lock to ensure that the Kafka producer is only initialized once.
        If the producer is not already set (self._producer is None), it attempts to create
        a new KafkaProducer using the provided configurations:
        bootstrap_servers, acks, retries, and compression_type.
        """
        with self._producer_lock:
            if self._producer is None:
                try:
                    self._producer = KafkaProducer(
                        bootstrap_servers=self.bootstrap_servers,
                        value_serializer=lambda v: json.dumps(v).encode(
                            'utf-8'
                        ),
                        acks=self.acks,
                        retries=self.retries,
                        linger_ms=self.linger_ms,
                        batch_size=self.batch_size,
                        compression_type=self.compression_type,
                    )
                    logger.info(
                        "Kafka producer initialized asynchronously "
                        "with bootstrap servers: %s, retries: %s, acks: %s, "
                        "linger_ms: %s, batch_size: %s, compression: %s",
                        self.bootstrap_servers,
                        self.retries,
                        self.acks,
                        self.linger_ms,
                        self.batch_size,
                        self.compression_type
                    )
                except (
                        NoBrokersAvailable,
                        NodeNotReadyError,
                        KafkaTimeoutError,
                        InvalidConfigurationError,
                        UnsupportedVersionError,
                ) as err:
                    logger.error(
                        "Failed to initialize Kafka producer asynchronously: %s. Error: %s",
                        type(err).__name__,
                        err
                    )
                    self._producer = None
                except Exception as err:  # pylint: disable=W0703
                    logger.error(
                        "Unexpected error during Kafka producer asynchronous initialization: %s",
                        err
                    )
                    self._producer = None

    def _reinitialize_producer(self) -> None:
        """Reinitialize the Kafka producer.

        The method first closes the existing producer (if any) and then attempts to get a new
        producer instance. It logs a warning before reinitialization and an appropriate
        message based on the outcome.
        """
        logger.warning('Reinitializing Kafka producer...')
        self.close_producer()
        self.get_producer()  # get producer will reinitialize the producer.
        if self._producer:
            logger.info(
                'Kafka producer reinitialized successfully...'
            )
        else:
            logger.error(
                'Failed to reinitialize Kafka producer.'
            )

    def _start_health_check_thread(self) -> None:
        """Start the background health check thread.

        The thread runs as a daemon and periodically checks the Kafka producer's
        health by invoking _health_check_loop."""
        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True
        )
        self._health_check_thread.start()

    def _health_check_loop(self) -> None:
        """Periodically verify the Kafka producer's health.

        This loop runs indefinitely, checking the health at intervals specified by
        health_check_interval. If the producer is found to be unhealthy,
        it attempts reinitialization.
        """
        while True:
            if not self.is_producer_healthy():
                self._reinitialize_producer()
            time.sleep(self.health_check_interval)

    @staticmethod
    def _validate_non_negative(input_val: int) -> int:
        """
        Validates that the 'input_val' is a non-negative integer.

        It should ensure that the provided parameter is an integer that is zero or positive.

        Args:
            input_val (int): The value to validate.

        Returns:
            int: The validated, non-negative integer.

        Raises:
            ValueError: If the provided value is not an integer or is negative.
        """
        if not isinstance(input_val, int) or input_val < 0:
            raise ValueError(
                f"Invalid value: {input_val}. Value must be a non-negative integer."
            )
        return input_val

    @staticmethod
    def _validate_acks(acks: Union[int, str]) -> Union[int, str]:
        """Validates the 'acks' parameter.

        It should ensure that the provided 'acks' parameter is one of
        the allowed values: 0, 1, -1, or 'all'.

        Args:
            acks (Union[int, str]): The acknowledgment setting to be validated.

        Returns:
            Union[int, str]: The validated 'acks' parameter.

        Raises:
            ValueError: If the provided value is not among the allowed options.
        """
        allowed_acks = {0, 1, -1, 'all'}
        if acks not in allowed_acks:
            raise ValueError(
                f"Invalid acks value: {acks}. Allowed values are {allowed_acks}.",
            )
        return acks
