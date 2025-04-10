# Account microservice

![Build Status](https://github.com/hokushin118/account-service/actions/workflows/ci.yml/badge.svg)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9](https://img.shields.io/badge/Python-3.9-green.svg)](https://shields.io/)

This repository provides the implementation for the `account-service`, a
cloud-native microservice built to **scale horizontally and handle high volumes
of requests efficiently.**

## Microservice Purpose: Account Management

The `account-service` is a cloud-native microservice designed to provide robust
and scalable account management capabilities. Its primary function is to handle
**CRUD (Create, Read, Update, Delete)** operations for **Account** entities.

**Key Responsibilities:**

* **Account Creation:** Provides an endpoint to register new user accounts.
* **Account Retrieval:** Enables fetching single accounts by their unique
  identifiers and listing all accounts.
* **Account Modification:** Supports full and partial updates of existing
  account information.
* **Account Deletion:** Allows for the removal of accounts.

**Design Principles:**

* **Scalability:** Designed to handle a large volume of account-related
  requests.
* **Reliability:** Implemented with error handling and robust data validation.
* **Maintainability:** Follows clean code principles and adheres to best
  practices.
* **Cloud-Native:** Built to leverage cloud infrastructure and
  containerization.

## Key Components and Libraries

This microservice is built using the following core technologies:

* **[Python 3.9](https://www.python.org/downloads/release/python-390/):**
    * The primary programming language used for development.
    * Chosen for its readability, extensive libraries, and strong community
      support.
* **[Flask](https://flask.palletsprojects.com):**
    * A lightweight and flexible web framework for Python.
    * Used to create the RESTful API endpoints and handle HTTP requests.
    * Allows for rapid development and easy prototyping.

**Additional Libraries and Tools:**

* **(Add other relevant libraries and tools here, e.g.,):**
    * **SQLAlchemy:** For database interaction.
    * **Flask-Migrate:** For database migrations.
    * **Pydantic:** For data validation.
    * **Gunicorn:** For WSGI HTTP server.
    * **unittest:** For unit testing.
    * **pylint:** For linting.

**Rationale:**

* [Python 3.9](https://www.python.org/downloads/release/python-390/)
  provides a stable and modern environment for development.
* [Flask](https://flask.palletsprojects.com)'s simplicity and extensibility
  make it an ideal choice for building
  microservices.
* The additional libraries are selected based on their functionality and
  suitability for the project's requirements.

## Prerequisites

To develop and run this project, you'll need the following tools and software
installed:

**Required:**

* **Python 3.9:**
    * Download and install Python 3.9 from the official
      website: [Python 3.9 Downloads](https://www.python.org/downloads/release/python-390/)
    * Ensure
      that [Python 3.9 Downloads](https://www.python.org/downloads/release/python-390/)
      is added to your system's PATH environment variable.
* **Docker Desktop:**
    * Install Docker Desktop for your operating
      system: [Docker Desktop Downloads](https://www.docker.com/products/docker-desktop)
    * Docker is essential for running infrastructure services and
      containerizing the application.

**Optional (Recommended for Development):**

* **Integrated Development Environment (IDE):**
    * Choose an IDE for efficient development:
        * [PyCharm](https://www.jetbrains.com/pycharm) (Recommended for Python
          development)
        * [Visual Studio Code](https://code.visualstudio.com) (Highly versatile
          and extensible)

**Operating System Compatibility:**

* While development has been primarily conducted
  on [Red Hat Enterprise Linux for Workstations](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux/workstations),
  this project is designed to be cross-platform compatible.
* **Gunicorn and Windows:**
    * This project uses Gunicorn as the WSGI HTTP server for local development.
    * Gunicorn is designed for Unix-like operating systems (Linux, macOS).
    * To run the application locally on Windows, it is highly recommended to
      use Docker.
    * Follow the instructions for installing docker on windows found
      here: [Docker for Windows Installation](https://docs.docker.com/desktop/setup/install/windows-install/).

**Important Notes:**

* Ensure that all required software is installed and configured correctly
  before proceeding with development.
* Using a virtual environment for Python development is strongly recommended to
  isolate project dependencies.
* If you are having issues with gunicorn on windows, use docker.

## Project Versioning

This project adheres to [Semantic Versioning 2.0.0](https://semver.org) for
managing releases.

**Version File:**

* The current project version is defined in the `VERSION` file, located in the
  root directory of the repository.
* This file contains a single line representing the version number.

**Versioning Scheme:**

* The version number follows the format `X.Y.Z`, where:
    * `X` (Major Version): Incremented when incompatible API changes are made.
    * `Y` (Minor Version): Incremented when new functionality is added in a
      backward-compatible manner.
    * `Z` (Patch Version): Incremented when backward-compatible bug fixes are
      made.

**Example:**

* `1.2.3` indicates major version 1, minor version 2, and patch version 3.

**Benefits of Semantic Versioning:**

* **Clarity:** Provides a clear indication of the type of changes included in
  each release.
* **Compatibility:** Helps users understand the potential impact of upgrading
  to a new version.
* **Automation:** Enables automated dependency management and release
  processes.

**Updating the Version:**

* When making changes to the project, update the `VERSION` file accordingly.
* Follow the [Semantic Versioning 2.0.0](https://semver.org) rules to determine
  which part of the version number to increment.

**Release Notes:**

* Each release should be accompanied by detailed release notes that describe
  the changes made.

## Environment Profiles

This microservice utilizes distinct environment profiles to manage
infrastructure and application configurations for different stages of
development and deployment.

**Available Profiles:**

* **development (default):**
    * Used for local development and testing.
    * Provides a development-friendly configuration.
* **docker:**
    * Used for running microservices within Docker containers.
    * Configures the application for a containerized environment.
* **production:**
    * Used for deploying microservices in a production environment.
    * Optimized for performance and security.

**Profile-Specific Environment Variables:**

Environment variables specific to each profile are defined in `.env.<profile>`
files located in the microservice's root directory.

* `.env`: Default environment variables (development profile).
* `.env.docker`: Environment variables for the Docker profile.
* `.env.production`: Environment variables for the production profile.

**Important Security Note (Production):**

* The `.env.production` file may contain sensitive information (e.g., database
  credentials, API keys). **Never commit this file to a version control
  repository.** Use secure methods for deploying production secrets, such as
  environment variables managed by your deployment platform or dedicated secret
  management tools.

**Setting the Active Profile:**

The active profile is determined by the `APP_SETTINGS` environment variable.

* Example (setting the Docker profile):
    ```bash
    export APP_SETTINGS=docker
    ```

## Local Development Setup

This section outlines the steps to set up and run the microservice in a local
development environment.

**1. Start Infrastructure Services:**

* Ensure that the necessary infrastructure services (e.g., databases, message
  queues) are running.
* Refer to
  the [Local Development](https://github.com/hokushin118/cba-devops/blob/main/README.md#local-development)
  section of the `cba-devops` repository's README for detailed instructions on
  setting up these services.

**2. Clone the Repository:**

* Clone the `account-service` repository to your local machine:

    ```bash
    git clone [https://github.com/hokushin118/account-service.git](https://github.com/hokushin118/account-service.git)
    ```

**3. Navigate to the Project Directory:**

* Change your current directory to the cloned repository:

    ```bash
    cd account-service
    ```

**4. Create and Activate a Virtual Environment:**

* Create a virtual environment to isolate project dependencies:

    ```bash
    python3.9 -m venv .venv
    ```

    * Note: Ensure you have Python 3.9 installed. Adjust the version if needed.

* Activate the virtual environment:

    ```bash
    source .venv/bin/activate  # On macOS/Linux
    .venv\Scripts\activate     # On Windows
    ```

**5. Install Dependencies:**

* Install the required Python packages using `pip`:

    ```bash
    python3.9 -m pip install -r requirements.txt
    ```

**6. Install or upgrade the cba-core-lib shared library from test.pypi.org:**

* To install or upgrade the library from the test PyPI repository, use the
  following command:

    ```bash
    pip install --index-url [https://test.pypi.org/simple/](https://test.pypi.org/simple/) --upgrade cba-core-lib
    ```

* To verify the installation and check the library's details, use the following
  command:

    ```bash
    pip show cba-core-lib
    ```

This command will display information about the installed `cba-core-lib`
library, including its version, location, and dependencies. It helps confirm
that the package was installed correctly.

**7. Apply Database Migrations:**

* Apply any pending database migrations to update the database schema:

    ```bash
    flask db upgrade
    ```

**8. Run the Microservice:**

* Start the microservice using the `wsgi.py` file:

    ```bash
    python3.9 wsgi.py
    ```

* The microservice will be accessible at `http://127.0.0.1:5000` (or the port
  specified in your application's configuration).

**Important Notes:**

* Verify that your application's configuration is correctly set up for the
  local development environment.
* If you encounter any dependency issues, ensure that your virtual environment
  is activated and that you have the correct Python version.
* When you are finished, deactivate the virtual environment:

    ```bash
    deactivate
    ```

## Database Configuration

This microservice relies on a PostgreSQL database for persistent account data.

**Database Requirements:**

* **PostgreSQL Instance:** A running PostgreSQL instance is required.
* **Port:** The instance must be accessible on port `5432`.
* **Database Name:** A database named `account_db` must exist.
* **User Credentials:** A database user named `cba` with the
  password `pa$$wOrd123!` must be created.

**Example (Local Development):**

* If you're using Docker Compose, the `docker-compose.test.yml` file will set
  up a suitable PostgreSQL instance.
* Otherwise, ensure you have a local PostgreSQL instance running with the
  specified database and user credentials.

## Running the Microservice with Docker

This section describes how to build and run the microservice using Docker.

**1. Build the Docker Image:**

* Navigate to the directory containing microservice `Dockerfile` (root
  directory of microservice).
* Use the following command to build the Docker image:

    ```bash
    docker build -t account-service .
    ```

    * `docker build`: Builds a Docker image.
    * `-t account-service`: Tags the image with the name `account-service`.
    * `.`: Specifies the build context (current directory).

**2. Run the Docker Container:**

* Use the following command to run the Docker container:

    ```bash
    docker run -p 5000:5000 account-service
    ```

    * `docker run`: Runs a Docker container.
    * `-p 5000:5000`: Maps port 5000 on the host to port 5000 in the container.
    * `account-service`: Specifies the image to run.

**Important Notes:**

* Ensure that Docker is installed and running on your system.
* Verify that your `Dockerfile` is correctly configured.
* The `-p 5000:5000` option maps the container's port to the host. If your
  application uses a different port, adjust the mapping accordingly.
* If you are running a database or other dependencies, you will need to run
  them as separate containers or use Docker Compose.
* To run the container in detached mode (background), add the `-d` flag:

    ```bash
    docker run -d -p 5000:5000 account-service
    ```
* To remove the container after stopping it, add the `--rm` flag:

    ```bash
    docker run --rm -p 5000:5000 account-service
    ```

* To run a specific version of the image, use the tag. For example:

    ```bash
    docker run -p 5000:5000 account-service:v1
    ```

## Running the Microservice with Docker Compose

This section outlines how to run the microservice using Docker Compose,
including infrastructure setup, database migrations, and service access.

**1. Start Infrastructure Services:**

* Before running the microservice, ensure that the necessary infrastructure
  services (e.g., databases, message queues) are running.
* Refer to
  the [Local Development](https://github.com/hokushin118/cba-devops/blob/main/README.md#local-development)
  section of the README for detailed instructions.

**2. Build and Run the Microservice:**

* Before executing any Docker Compose commands, ensure you are in the root
  directory of the microservice repository.
* Use the following command to navigate to the root directory, if needed:

    ```bash
    cd /path/to/account-service
    ```

* Use Docker Compose to build and run the microservice, along with any
  profile-specific configurations.
* Replace `<profile>` with the desired profile (e.g., `dev`, `test`, `prod`).

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.<profile>.yml up --build
    ```

* Example (dev profile):

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
    ```

* To run the services in detached mode (background), add the `-d` flag:

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
    ```

**3. Apply Database Migrations:**

* After the services are running, apply any pending database migrations.
* This step ensures that the database schema is up-to-date.

    ```bash
    flask db-upgrade
    ```

**4. Access the Microservice:**

* Once the microservice is running, you can access it
  at `http://127.0.0.1:5000`.
* Replace `5000` with the port defined in your `docker-compose.<profile>.yml`
  file if necessary.

**5. Stop the Services:**

* To stop the services, press **Ctrl+C** in the terminal where they are
  running (if not detached), or use the following command:

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.<profile>.yml down
    ```

* Example (dev profile):

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.dev.yml down
    ```

* To remove volumes as well, add the `-v` flag:

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
    ```

**6. Extending Docker Compose Configuration:**

* For more details on extending Docker Compose configurations,
  see: [Extend your Compose files](https://docs.docker.com/compose/how-tos/multiple-compose-files/extends)

## Running Tests

### Introduction

The microservice utilizes unit tests to verify individual components and
integration tests to ensure system-wide functionality.

**1. Unit Tests: Verifying Individual Components**

* **Focus on Isolation:**
    * Unit tests are designed to isolate and examine the smallest testable
      parts of the microservice, typically individual functions, methods, or
      classes.
    * This isolation is achieved through techniques like mocking and stubbing,
      which replace external dependencies with controlled simulations.
* **Granular Validation:**
    * The primary goal is to ensure that each component behaves as expected in
      isolation. This allows to pinpoint bugs at the most granular level,
      making debugging significantly easier.
* **Speed and Efficiency:**
    * Unit tests are generally fast to execute, enabling rapid feedback during
      development. This promotes a test-driven development (TDD) approach,
      where tests are written before the actual code.
* **Benefits:**
    * Improved code quality and maintainability.
    * Early detection of bugs.
    * Facilitates refactoring by providing confidence in the code's behavior.
    * Enhanced code documentation through executable examples.

**2. Integration Tests: Ensuring System-Wide Functionality**

* **Focus on Interactions:**
    * Integration tests go beyond individual components and examine how
      different parts of the microservice interact with each other.
    * This includes testing the communication between modules, services,
      databases, and external APIs.
* **Benefits:**
    * Detection of integration issues that are not apparent in unit tests.
    * Validation of system-level functionality and performance.
    * Increased confidence in the microservice's overall stability.
    * Verifying that all parts of the system work together.

### Execution

To execute the microservice's tests, follow these steps:

1. **Start Infrastructure Services:**
    * Ensure that the necessary infrastructure services (e.g., databases,
      message queues) are running using Docker Compose. For more information,
      see
      the [Start Infrastructure Services](https://github.com/hokushin118/cba-devops?tab=readme-ov-file#local-development)
      section of the README.

2. **Apply Database Migrations:**
    * Before applying database migration, ensure you are in the root directory
      of the microservice repository.
    * Use the following command to navigate to the root directory, if needed:

    ```bash
    cd /path/to/account-service
    ```

    * Apply any pending database migrations to ensure the database schema is
      up-to-date.

   ```bash
   flask db-upgrade
   ```

3. **Run Unit Tests:**
    * Execute the microservice's unit tests using `nosetests`.
   ```bash
   nosetests -v --with-spec --spec-color tests/unit
   ```
    * `nosetests`: Executes the nosetests test runner.
    * `-v`: Enables verbose output.
    * `--with-spec`: Enables the `nose-spec` plugin for a more readable test
      output.
    * `--spec-color`: Enables colored output for `nose-spec`.
    * `tests/unit`: Specifies the directory where nosetests should discover and
      execute unit tests.

4. **Run Integration Tests:**
    * Execute the microservice's integration tests using `nosetests`.
   ```bash
   RUN_INTEGRATION_TESTS=true nosetests -v --with-spec --spec-color tests/integration
   ```
    * `RUN_INTEGRATION_TESTS=true`: Enables the execution of integration tests.
    * `nosetests`: Executes the nosetests test runner.
    * `-v`: Enables verbose output.
    * `--with-spec`: Enables the `nose-spec` plugin for a more readable test
      output.
    * `--spec-color`: Enables colored output for `nose-spec`.
    * `tests/integration`: Specifies the directory where nosetests should
      discover and execute integration tests.

**Important Notes:**

* Verify that your application's configuration is set up correctly for the
  testing environment.
* Review the test output for any failures or errors.
* If you are using a different testing framework than nose, update the testing
  command accordingly.

## Lint

This project uses `pylint` to enforce code quality and style standards. To lint
the code, use the following command:

```bash
pylint service/
```

## Environment Variables

Environment variables for each profile are configured in the `.env` files.

## Endpoints

This section describes the available API endpoints.

**General Endpoints:**

* `/api` (GET):
    * Returns a welcome message indicating the API is running.
    * Example Response: `{"message": "Welcome to the API!"}`
* `/api/health` (GET):
    * Provides the health status of the service.
    * Response: `{"status": "UP"}` (Note: Currently always "UP").
* `/api/info` (GET):
    * Returns service information, including name, version, and uptime.
    * Example
      Response: `{"name": "Account Service", "version": "1.0.0", "uptime": "1d 2h 3m"}`

**Account Management (v1):**

* `/api/v1/accounts` (POST):
    * Creates a new account.
    * Request Body: JSON object containing account details (
      e.g., `{"name": "testuser", "email": "test@example.com"}`).
    * Response: JSON object representing the created account.
* `/api/v1/accounts` (GET):
    * Lists all accounts.
    * Response: JSON array of account objects.
* `/api/v1/accounts/{account_id}` (GET):
    * Retrieves a specific account by its unique ID.
    * `{account_id}`: UUID of the account.
    * Response: JSON object representing the requested account.
* `/api/v1/accounts/{account_id}` (PUT):
    * Updates an existing account. Replaces the entire account object.
    * `{account_id}`: UUID of the account.
    * Request Body: JSON object containing the updated account details.
    * Response: JSON object representing the updated account.
* `/api/v1/accounts/{account_id}` (PATCH):
    * Partially updates an existing account. Updates only the provided fields.
    * `{account_id}`: UUID of the account.
    * Request Body: JSON object containing the fields to update.
    * Response: JSON object representing the updated account.
* `/api/v1/accounts/{account_id}` (DELETE):
    * Deletes an account.
    * `{account_id}`: UUID of the account.
    * Response: Response: Success status (204 No Content).

**Notes:**

* `{account_id}` refers to a version
  4 [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier) (
  Universally Unique Identifier).
* Request and response formats are in JSON.
* Error handling and response codes are omitted for brevity. Refer to the API
  documentation ([Swagger](https://swagger.io)) for detailed error information.

## API Versioning

This API employs path-based versioning to manage changes and ensure backward
compatibility.

**Current Version:**

* The current API version is **v1**.
* All API endpoints are prefixed with `/api/v1/`.
* Example: `/api/v1/accounts`

**Future Versions:**

* When significant changes are introduced to the API, a new version will be
  released (e.g., **v2**).
* New versions will be accessible through their respective path prefixes (
  e.g., `/api/v2/`).
* Previous versions will be deprecated, and a migration period will be provided
  before they are removed.

**Deprecation Policy:**

* A clear deprecation notice will be provided when a new API version is
  released.
* The deprecation period will allow developers sufficient time to migrate to
  the latest version.
* The exact deprecation period will be announced in the release notes and
  documentation.

**Benefits of Versioning:**

* **Backward Compatibility:** Allows existing applications to continue
  functioning without immediate changes.
* **Controlled Updates:** Provides a structured way to introduce breaking
  changes.
* **Improved Communication:** Clearly indicates which version is being used.

## API Documentation

This API utilizes [Swagger](https://swagger.io) for interactive documentation.

**Accessing Swagger:**

* You can access the [Swagger](https://swagger.io) UI
  at [http://127.0.0.1:5000/apidocs](http://127.0.0.1:5000/apidocs).
* This interface allows you to explore the available API endpoints, understand
  their parameters, and even make test requests directly from your browser.

**Enabling/Disabling Swagger:**

* [Swagger](https://swagger.io) can be conditionally enabled or disabled using
  the `SWAGGER_ENABLED` environment variable.
* To enable Swagger, set `SWAGGER_ENABLED` to `true` (or any value that your
  application interprets as true).
* To disable Swagger, set `SWAGGER_ENABLED` to `false` (or omit the variable
  entirely).
* Example (using bash):
    ```bash
    export SWAGGER_ENABLED=true
    ```

**Important Notes:**

* Ensure that your application is running on port 5000 (or the port specified
  in your application's configuration) for the [Swagger](https://swagger.io) UI
  to be accessible.
* In production environments, it's generally recommended to disable Swagger for
  security reasons, unless access is carefully controlled.

## Prometheus Monitoring

For more information, see
the [Prometheus Monitoring](https://github.com/hokushin118/cba-devops?tab=readme-ov-file#prometheus-monitoring)
section of the README.

## Deployment on Kubernetes

For more information, see
the [Deployment on Kubernetes](https://github.com/hokushin118/cba-devops?tab=readme-ov-file#deployment-on-kubernetes)
section of the README.

## Deployment on Red Hat OpenShift with Tekton

For more information, see
the [Deployment on Red Hat OpenShift with Tekton](https://github.com/hokushin118/cba-devops?tab=readme-ov-file#deployment-on-red-hat-openshift-with-tekton)
section of the README.

**Running Pipelines:**

1. To start CI/CD pipeline
   on [Red Hat OpenShift](https://www.redhat.com/en/technologies/cloud-computing/openshift),
   use the following command:

```bash
tkn pipeline start cba-pipeline \
            -p repo-url="https://github.com/hokushin118/account-service.git" \
            -p branch="main" \
            -p build-image=hokushin/account-service:latest \
            -p deploy-enabled=false \
            -w name=cba-pipeline-workspace,claimName=cba-pipeline-pvc \
            -s pipeline \
            --showlog
```

2. To start the database migration revert pipeline
   on [Red Hat OpenShift](https://www.redhat.com/en/technologies/cloud-computing/openshift),
   use the following command:

```bash
tkn pipeline start cba-pipeline \
            -p repo-url="https://github.com/hokushin118/account-service.git" \
            -p branch="main" \
            -p revision="1234abcd" \
            -w name=cba-pipeline-workspace,claimName=cba-pipeline-pvc \
            -s pipeline \
            --showlog
```

## Keycloak Identity and Access Management (IAM)

For more information, see
the [Keycloak IAM](https://github.com/hokushin118/cba-devops?tab=readme-ov-file#keycloak-identity-and-access-management-iam)
section of the README.

## Audit with Kafka

The **@audit_log** decorator is used to automatically log audit events to a
dedicated Kafka topic. It is applied to Flask route handlers to ensure that all
requests to those endpoints are captured for auditing purposes.

**Purpose:**

This feature provides a centralized and asynchronous mechanism for tracking and
monitoring access to sensitive resources. Audit logs are sent to Kafka,
enabling efficient processing, storage, and analysis of audit data.

**Usage:**

Add the **@audit_log** decorator directly above the Flask route handler you
wish to audit.

**Example:**

```python
@app.route('/accounts', methods=['GET'])
@audit_log
def list_accounts():
    """Lists all accounts."""
    accounts = [{"id": 1, "name": "Example Account"}]
    return jsonify(accounts)
```

**Configuration:**

Audit logging behavior is controlled via environment variables:

* `KAFKA_AUDIT_BOOTSTRAP_SERVERS`: Kafka broker addresses (default: kafka:
  9093).
* `KAFKA_AUDIT_TOPIC`: Kafka topic to which audit events are sent (default:
  audit-events).
* `KAFKA_AUDIT_RETRIES`: Number of retries for Kafka producer (default: 5).
* `KAFKA_AUDIT_ACKS`: Kafka acknowledgment setting (default: 1).
* `KAFKA_AUDIT_COMPRESSION`: Kafka compression type (default: gzip).
* `KAFKA_HEALTH_CHECK_INTERVAL`: Kafka health check interval in seconds
  (default: 60).
* `AUDIT_ENABLED`: Enables or disables audit logging, set to 'true' to
  enable.

**Audit Log Format (JSON):**

Each audit log entry is a JSON object with the following fields:

* `timestamp`: ISO 8601 formatted timestamp of the request (UTC).
* `user`: User making the request (extracted from JWT,
  defaults to Anonymous").
* `method`: HTTP request method (e.g., GET, POST, PUT, DELETE).
* `url`: Full URL of the request.
* `request_headers`: HTTP request headers (excluding sensitive data like
  Authorization).
* `request_body`: Request body (JSON or plain text).
* `response_status`: HTTP response status code.
* `response_body`: Response body (JSON or plain text).
* `client_ip`: Client IP address.
* `correlation_id`: Unique correlation ID for tracking the request.

**Error Handling:**

If audit logging fails (e.g., Kafka connection issues), the original request
will still be processed, and an error will be logged.

**Important Considerations:**

* JWT Authentication: The @audit_log decorator assumes JWT authentication is
  used to identify users.
* Environment Variables: Ensure that the necessary environment variables are
  set correctly.
* Kafka Configuration: Configure Kafka brokers and topics appropriately.

For more information, see
the [Audit with Kafka](https://github.com/hokushin118/cba-devops?tab=readme-ov-file#audit-with-kafka)
section of the README.

## Logging Configuration

This section describes a utility function designed to establish consistent
logging practices within containerized environments, ensuring clear separation
between informational and error logs.

### `init_logging(app, log_level=logging.INFO)`

This function configures the application's logger to direct log messages to
either `stdout` or `stderr`, based on their severity level.

**Parameters:**

* `app`: The application instance (e.g., a Flask application object).
* `log_level`: The minimum log level for messages to be directed to `stdout` (
  default: `logging.INFO`). Messages with this level or lower (e.g., `DEBUG`)
  will be sent to `stdout`. Messages above this level, but
  below `logging.ERROR`, will also be sent to `stdout`.

**Behavior:**

* **Consistent Log Format:** Configures a standardized log message format,
  including:
    * Timestamp (UTC)
    * Log level
    * Module name
    * Log message
* **`stdout` and `stderr` Handlers:** Sets up `logging.StreamHandler` objects
  to direct log messages:
    * Messages with a log level of `log_level` or lower are sent to `stdout`.
    * Messages with a log level of `logging.ERROR` or `logging.CRITICAL` are
      sent to `stderr`.
* **Preventing Duplicate Logs:** Clears any existing log handlers associated
  with the application's logger to avoid duplicate log entries.
* **Application-Wide Log Level:** Sets the overall log level for the
  application's logger to the provided `log_level`.
* **Initialization Confirmation:** Logs an informational message upon
  successful setup, including the configured log level.

**Purpose:**

This function is particularly useful in containerized environments (like
Docker, Kubernetes or OpenShift), where it's essential to separate
informational and error logs for efficient monitoring and log aggregation. By
directing logs to `stdout` and `stderr`, container orchestrators can easily
capture and process log data.

## Database Migrations

The microservice uses [Flask-Migrate](https://flask-migrate.readthedocs.io) for
database migrations. The database
migrations are stored in the `migrations` folder.

To initialize the database migrations, use the following command:

```bash
flask db-init
```

To generate an initial migration, use the following command:

```bash
flask db-migrate -m 'Initial migration.'
```

To apply the database migration, run the following command:

```bash
flask db-upgrade
```

To create a new database migration, use the following command:

```bash
flask db-revision -m "<database migration version>_<database migration description>" --autogenerate
```

For example:

```bash
flask db-revision -m "20250224 - initial" --autogenerate
```

To apply the database migrations, use the following command:

```bash
flask db-upgrade
```

To get the database migration history, use the following commands:

```bash
flask db-history
flask db-history -v
flask db-history --verbose
flask db-history --rev-range 1234abcd:5678efgh
```

To rollback the database migrations, run the following commands:

```bash
flask db-downgrade
flask db-downgrade <number_of_steps>
flask db-downgrade <revision_id>
```

### Database Migration Versioning

The database migration versioning is based on the date of the migration. The
date format is `YYYYMMDD`. The date is followed by a underscore and a short
description of the migration.

For example:

```
20250224_<short description of the migration>
```
