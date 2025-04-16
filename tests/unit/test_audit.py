"""
Audit Utils Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from unittest import TestCase
from unittest.mock import Mock, patch

from cba_core_lib.kafka import KafkaProducerManager
from cba_core_lib.kafka.configs import KafkaProducerConfig
from flask import Flask, Response
from flask_jwt_extended import JWTManager

from service.common.audit import AuditLogger
from tests.utils.constants import TEST_TOPIC, JWT_SECRET_KEY
from tests.utils.utils import DummyRecordMetadata

# Mock environment variables for testing
os.environ['KAFKA_AUDIT_BOOTSTRAP_SERVERS'] = 'test-kafka:9092'
os.environ['KAFKA_AUDIT_TOPIC'] = 'test-audit-events'
os.environ['KAFKA_AUDIT_RETRIES'] = '1'
os.environ['KAFKA_AUDIT_ACKS'] = '1'
os.environ['KAFKA_AUDIT_LINGER_MS'] = '1'
os.environ['KAFKA_AUDIT_BATCH_SIZE'] = '16384'
os.environ['KAFKA_AUDIT_COMPRESSION'] = 'gzip'
os.environ['KAFKA_AUDIT_HEALTH_CHECK_INTERVAL'] = '60'


######################################################################
#  AUDIT TEST CASES
######################################################################
class TestAuditLogger(TestCase):
    """The AuditLogger Tests."""

    def setUp(self):
        """Set up test environment."""
        self.app = Flask(__name__)
        self.app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
        self.jwt = JWTManager(self.app)
        self.audit_logger = AuditLogger()

    def test_audit_logger_initialization(self):
        """It should initialize AuditLogger with Kafka configs and producer manager."""
        self.assertIsInstance(self.audit_logger.config, KafkaProducerConfig)
        self.assertIsInstance(
            self.audit_logger.producer_manager,
            KafkaProducerManager
        )

    def test_get_request_body_or_none_json(self):
        """It should return request body as dict if JSON, or None if no body."""
        with self.app.test_request_context(json={'key': 'value'}):
            self.assertEqual(
                AuditLogger.get_request_body_or_none(),
                {'key': 'value'}
            )

        with self.app.test_request_context():
            self.assertIsNone(AuditLogger.get_request_body_or_none())

    def test_get_request_body_or_none_text(self):
        """It should return request body as string if text."""
        with self.app.test_request_context(data='test text'):
            self.assertEqual(
                AuditLogger.get_request_body_or_none(),
                'test text'
            )

    def test_on_send_success(self):
        """It should log successful Kafka send with metadata."""
        mock_record_metadata = Mock()
        mock_record_metadata.topic = TEST_TOPIC
        mock_record_metadata.partition = 0
        mock_record_metadata.offset = 123
        key = b'test-key'

        with patch('service.common.audit.logger.info') as mock_logger_info:
            AuditLogger.on_send_success(mock_record_metadata, key)
            mock_logger_info.assert_called_once()

    def test_on_send_error(self):
        """It should log Kafka send error with exception details."""
        mock_exception = Exception('test error')
        with patch('service.common.audit.logger.error') as mock_logger_error:
            AuditLogger.on_send_error(mock_exception)
            mock_logger_error.assert_called_once()

    @patch('service.common.audit.AuditLogger.get_request_body_or_none')
    @patch('cba_core_lib.kafka.KafkaProducerManager.get_producer')
    @patch('flask_jwt_extended.verify_jwt_in_request')
    @patch('flask_jwt_extended.get_jwt_identity')
    def test_audit_log_kafka(
            self,
            mock_get_jwt_identity,
            mock_verify_jwt_in_request,
            mock_get_producer,
            mock_get_request_body
    ):
        """It should decorate a route, log audit data, and send to Kafka."""

        def test_route():
            return Response(
                response='OK',
                status=200,
                mimetype='application/json'
            )

        mock_get_request_body.return_value = {'test': 'data'}
        mock_producer = Mock()
        mock_get_producer.return_value = mock_producer
        mock_get_producer.send.return_value = Mock()
        mock_get_jwt_identity.return_value = 'test_user'
        mock_verify_jwt_in_request.return_value = None

        decorated_route = self.audit_logger.audit_log_kafka(test_route)

        with self.app.test_request_context(
                headers={'Authorization': 'Bearer test_token'},
                json={'test': 'data'}
        ):
            response = decorated_route()
            self.assertEqual(response.status_code, 200)

    @patch('service.common.audit.AuditLogger.get_request_body_or_none')
    @patch('cba_core_lib.kafka.KafkaProducerManager.get_producer')
    @patch('flask_jwt_extended.verify_jwt_in_request')
    @patch('flask_jwt_extended.get_jwt_identity')
    def test_audit_log_kafka_anonymous(
            self,
            mock_get_jwt_identity,
            mock_verify_jwt_in_request,
            mock_get_producer,
            mock_get_request_body
    ):
        """It should handle anonymous users and send audit data to Kafka."""

        def test_route():
            return Response(
                response='OK',
                status=200,
                mimetype='application/json'
            )

        mock_get_request_body.return_value = {'test': 'data'}
        mock_producer = Mock()
        mock_get_producer.return_value = mock_producer
        mock_get_producer.send.return_value = Mock()
        mock_get_jwt_identity.return_value = None
        mock_verify_jwt_in_request.return_value = None

        decorated_route = self.audit_logger.audit_log_kafka(test_route)

        with self.app.test_request_context(
                headers={'Authorization': 'Bearer test_token'},
                json={'test': 'data'}
        ):
            response = decorated_route()
            self.assertEqual(response.status_code, 200)


class TestCallbacks(TestCase):
    """Kafka Callback Functions Tests."""

    def test_on_send_success_logs_info(self):
        """It should log an info message with topic, key, partition, and offset o
        n successful send."""
        record_metadata = DummyRecordMetadata(TEST_TOPIC, 1, 42)
        key = b"test_key"
        with self.assertLogs(
                'service.common.audit',
                level='INFO'
        ) as common_module:
            AuditLogger.on_send_success(record_metadata, key)
            log_output = "\n".join(common_module.output)
            self.assertIn('Kafka message sent successfully', log_output)
            self.assertIn(TEST_TOPIC, log_output)
            self.assertIn('test_key', log_output)
            self.assertIn('42', log_output)

    def test_on_send_error_logs_error(self):
        """It should log an error message with the provided error details on send failure."""
        error = Exception('Test error')
        with self.assertLogs(
                'service.common.audit',
                level='ERROR'
        ) as common_module:
            AuditLogger.on_send_error(error)
            log_output = "\n".join(common_module.output)
            self.assertIn('Error occurred during Kafka send', log_output)
            self.assertIn('Test error', log_output)
