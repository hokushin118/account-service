"""
This module provides utility methods for use in tests.
"""
from typing import Union, Optional

from kafka.errors import KafkaConnectionError  # pylint: disable=E0401

from service.common.kafka_producer import KafkaProducerManager
from service.configs import KafkaProducerConfig
from service.schemas import AccountPagedListDTO, AccountDTO
from tests.utils.constants import TEST_TOPIC
from tests.utils.factories import AccountFactory


def create_account_paged_list_dto() -> AccountPagedListDTO:
    """Create a dummy AccountPagedListDTO for testing purposes.

    This function uses the AccountFactory to generate two dummy accounts,
    converts them into AccountDTO objects, and constructs a paginated DTO
    with preset pagination values and a total count.

    Returns:
        AccountPagedListDTO: A dummy paginated list of AccountDTO objects.
    """
    # Generate dummy accounts
    account1 = AccountFactory()
    account2 = AccountFactory()

    # Convert dummy accounts to DTOs
    account_dto1 = AccountDTO.model_validate(account1)
    account_dto2 = AccountDTO.model_validate(account2)

    # Assemble the DTOs into a list
    accounts = [account_dto1, account_dto2]

    # Create and return the paginated DTO.
    return AccountPagedListDTO(
        items=accounts,
        page=1,
        per_page=10,
        total=len(accounts)
    )


class DummyRecordMetadata:
    """DummyRecordMetadata is a mock class that simulates the RecordMetadata object returned
    by a KafkaProducer upon successful message send.

    It stores key information about the sent message, such as the topic,
    partition, and offset.
    """

    def __init__(self, topic, partition, offset):
        """Initialize the dummy record metadata with the given topic,
        partition, and offset.

        Args:
            topic: The Kafka topic to which the message was published.
            partition: The partition within the topic.
            offset: The offset of the message within the partition.
        """
        self.topic = topic
        self.partition = partition
        self.offset = offset


class DummyFuture:
    """DummyFuture is a mock future object representing the asynchronous result of a send operation.

    It should allow attaching callback and error callback functions that simulate handling of
    success or failure of the send operation.
    """

    def add_callback(self, function):
        """Simulate attaching a callback that is invoked upon a successful
        send.

        Args:
            function: The callback function to be executed, receiving dummy metadata.

        Returns:
            DummyFuture: The current DummyFuture instance (to allow chaining).
        """
        dummy_metadata = DummyRecordMetadata(
            TEST_TOPIC,
            0,
            0
        )
        function(dummy_metadata)
        return self

    def add_errback(self, function):
        """Simulate attaching an error callback that is invoked
        when a send error occurs.

        Args:
            function: The error callback function to be executed.

        Returns:
            DummyFuture: The current DummyFuture instance (to allow chaining).
        """
        function()
        return self


class DummyKafkaProducer:
    """A dummy KafkaProducer that simulates a healthy producer."""

    def __init__(self) -> None:
        """It should initialize a DummyKafkaProducer instance.

        Sets the 'closed' attribute to False indicating that the producer is active.
        """
        self.messages = []  # Record the sent messages
        self.closed = False

    def send(self, topic, key, value):
        """Simulate sending a message to Kafka by storing the message details.

        Args:
            topic: The Kafka topic to which the message is sent.
            key: The key of the message.
            value: The payload or content of the message.

        Returns:
            DummyFuture: A dummy future object simulating asynchronous send behavior.
        """
        self.messages.append((topic, key, value))
        return DummyFuture()

    def flush(self):
        """Simulate flushing any buffered messages.

        In this dummy implementation, no action is needed.
        """

    def close(self) -> None:
        """It should simulate closing the producer.

        Marks the producer as closed by setting the 'closed' attribute to True.
        """
        self.closed = True

    def partitions_for(self, topic: str) -> Optional[set[int]]:
        """It should return a dummy non-empty set for the internal consumer offsets topic,
        and None for any other topic.

        Args:
            topic (str): The topic name for which partitions are requested.

        Returns:
            set[int] or None: A set of partition numbers for the consumer offsets topic, or
            None if the topic is not recognized.
        """
        if topic == KafkaProducerManager.CONSUMER_OFFSETS_TOPIC:
            return {0, 1}
        return None


class DummyKafkaProducerError:
    """A dummy KafkaProducer that simulates failure in health check."""

    def partitions_for(self, topic: str) -> None:
        """It should simulate a failure when attempting to retrieve partition information.

        Args:
            topic (str): The name of the topic for which partition information is requested.

        Raises:
            KafkaConnectionError: Always raised to simulate a Kafka connection error.
        """
        raise KafkaConnectionError('Simulated connection error')


class DummyKafkaProducerConfig(KafkaProducerConfig):
    """A dummy KafkaProducerConfig for testing purposes."""

    def __init__(self,
                 bootstrap_servers: str,
                 retries: int,
                 acks: Union[int, str],
                 linger_ms: int,
                 batch_size: int,
                 health_check_interval: int,
                 compression_type: Optional[str] = 'gzip'
                 ) -> None:
        """
        Initialize the KafkaProducer configuration with test-specific settings.

        This constructor calls the base class constructor to initialize the configuration
        parameters such as bootstrap servers, retries, acknowledgments, linger time, batch size,
        and health check interval. Additionally, it sets the compression_type to "gzip" for testing.

        Args:
            bootstrap_servers (str): A comma-separated list of Kafka bootstrap servers.
            retries (int): The number of retry attempts for sending messages.
            acks (Union[int, str]): The acknowledgment level ('all', 0, 1, etc.).
            linger_ms (int): The maximum time (in milliseconds) to buffer data before sending.
            batch_size (int): The maximum size (in bytes) of a batch of messages.
            health_check_interval (int): The interval (in seconds) for performing health checks.
        """
        super().__init__(
            bootstrap_servers,
            retries,
            acks,
            linger_ms,
            batch_size,
            health_check_interval,
            compression_type
        )
