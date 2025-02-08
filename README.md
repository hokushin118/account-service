# Account microservice

## Microservice Purpose

The core purpose of the **Account** cloud-native microservice is to handle the
**CRUD** (Create, Read, Update, Delete) operations for **Account** objects.
It provides endpoints for creating new accounts, listing all accounts,
retrieving a specific account by ID, updating an account, partially updating an
account, and deleting an account.

## Key Components and Libraries

**Python 3.9**: The programming language used to implement the microservice.  
**Flask**: The web framework used to create the REST API.

## Local Development

To run the microservice locally, follow these steps:

1. Clone the repository to your local machine.

```bash
git clone https://github.com/hokushin118/account-service.git
```

2. Navigate to the project directory.

```bash
cd account-service
```

3. Create a virtual environment and activate it:

```bash
python3.9 -m pip install venv
python3.9 -m venv .venv
source .venv/bin/activate
```

4. Install the required dependencies using pip:

```bash
python3.9 -m pip install -r requirements.txt
```

5. Run the microservice

```bash
python3.9 wsgi.py
```

## Database

The microservice uses a **PostgreSQL** database to store account data. Make
sure you have **PostgreSQL** running locally on port **5432** with a database
named **account_db** and a user named **cba** with password **pa$$wOrd123!**.

The database schema is defined in the **init.sql** file located in the
**.infrastructure/postgres** directory.

Note that the **PostgreSQL** database is used bitnami docker image. This image
initializes the database using the **init.sql** file located in the
**docker-entrypoint-initdb.d** directory.

The following lines in the docker-compose file initialize the **init.sql**
file:

```
environment:
  - POSTGRESQL_INIT_FILE=/docker-entrypoint-initdb.d/init.sql  # Bitnami specific
volumes:
  - ./.infrastructure/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
```

## Run on Docker

To run the microservice using **Docker**, follow these steps:

1. Build the **Docker** image:

```bash
docker build -t account-service .
```

2. Run the **Docker** container:

```bash
docker run -p 5000:5000 account-service
```

## Run on Docker Compose

To run the microservice using **Docker Compose**, follow these steps:

1. Build and run the **Docker Compose** services:

```bash
docker compose up --build
```

or

```bash
docker compose up --build -d
```

You can access the microservice at http://127.0.0.1:5000.

To stop the services, press **Ctrl+C** in the terminal where the services are
running, or run:

```bash
docker compose down
```

or

```bash
docker compose down -v
```

## Run tests

To run the tests for the microservice, use the following command:

```bash
nosetests -v --with-spec --spec-color
```

Make sure you have **PostgreSQL** running locally on port **5432** with a
database named **postgres** and a user named **postgres** with password
**account_db**.

## Lint

To lint the code, use the following command:

```bash
pylint service/
```

## Environment Variables

You can set the environment variables for the profile in the **.env** files.

## Endpoints

/ (GET): The root endpoint. Returns a welcome message.
/health (GET): Returns the health status of the service (currently always
"UP").
/info (GET): Returns information about the service (name, version, uptime).
/accounts (POST): Creates a new account.
/accounts (GET): Lists all accounts.
/accounts/<int:account_id> (GET): Retrieves a specific account by ID.
/accounts/<int:account_id> (PUT): Updates an existing account.
/accounts/<int:account_id> (PATCH): Partially updates an existing account.
/accounts/<int:account_id> (DELETE): Deletes an account.

## Prometheus

Prometheus endpoint is available at:

http://localhost:19090/metrics

http://localhost:19090/targets
