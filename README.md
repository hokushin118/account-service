ccount microservice

![Build Status](https://github.com/hokushin118/account-service/actions/workflows/ci-build.yaml/badge.svg)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9](https://img.shields.io/badge/Python-3.9-green.svg)](https://shields.io/)

This repository contains the code for the **account-service**, a cloud-native
microservice.

## Microservice Purpose

The core purpose of the **account-service** cloud-native microservice is to
handle the **CRUD** (Create, Read, Update, Delete) operations for
**Account** objects. It provides endpoints for creating new accounts, listing
all accounts,
retrieving a specific account by ID, updating an account, partially updating an
account, and deleting an account.

## Key Components and Libraries

**Python 3.9**: The programming language used to implement the microservice.  
**Flask**: The web framework used to create the REST API.

## Prerequisites

- [Python 3.9](https://www.python.org/downloads/release/python-390/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)

## Project version

The project uses **semantic** versioning for its versioning scheme. The
versioning scheme is defined in the **VERSION** file located in the root
directory of the project. The version number is in the format **X.Y.Z**, where
**X** is the major version, **Y** is the minor version, and **Z** is the patch
version.

## Profiles

The microservice has three launching profiles:

**development** - (default, used for launching the microservice in a
development environment)
**docker** - (used for launching the microservice in a docker container)  
**production** - (used for launching the microservice in a production
environment)

The environment variables specific to profile are defined in the *
*.env.<pofile>** file located in the root directory of the microservice.

.env - - default (development) profile

.env.docker - docker profile

.env.production - production profile, never commit it to the repository

The profile is set using the **FLASK_DEBUG** environment variable.

```
export FLASK_DEBUG=docker 
```

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

5. Launch test infrastructure with **Docker Compose**:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up
```

6. Run the microservice

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
docker compose -f docker-compose.yml -f docker-compose-account.yml -f docker-compose.<profile>.yml up --build
```

For example, to run the services with the  **dev** profile, use the following
command:

```bash
docker compose -f docker-compose.yml -f docker-compose-account.yml -f docker-compose.dev.yml up --build
```

or

```bash
docker compose -f docker-compose.yml -f docker-compose-account.yml -f docker-compose.dev.yml up --build -d
```

You can access the microservice at http://127.0.0.1:5000.

To stop the services, press **Ctrl+C** in the terminal where the services are
running, or run:

```bash
docker compose -f docker-compose.yml -f docker-compose-account.yml -f docker-compose.<profile>.yml down
```

For example, to stop the services running with the  **dev** profile, use the
following command:

```bash
docker compose -f docker-compose.yml -f docker-compose-account.yml -f docker-compose.dev.yml down
```

or

```bash
docker compose -f docker-compose.yml -f docker-compose-account.yml -f docker-compose.dev.yml -v
```

For more details on extending **Docker Compose** configuration, see:
[Extend your Compose files](https://docs.docker.com/compose/how-tos/multiple-compose-files/extends)

## Run tests

1. Make sure you launch test infrastructure with **Docker Compose**:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up
```

2. To run the tests for the microservice, use the following command:

```bash
nosetests -v --with-spec --spec-color
```

## Lint

To lint the code, use the following command:

```bash
pylint service/
```

## Environment Variables

You can set the environment variables for the profile in the **.env** files.

## Endpoints

/api (GET): The root endpoint. Returns a welcome message.  
/api/health (GET): Returns the health status of the service (currently always
"UP").  
/api/info (GET): Returns information about the service (name, version,
uptime).  
/api/v1/accounts (POST): Creates a new account.  
/api/v1/accounts (GET): Lists all accounts.  
/api/v1/accounts/<int:account_id> (GET): Retrieves a specific account by ID.  
/api/v1/accounts/<int:account_id> (PUT): Updates an existing account.  
/api/v1/accounts/<int:account_id> (PATCH): Partially updates an existing
account.  
/api/v1/accounts/<int:account_id> (DELETE): Deletes an account.

## API Versioning

The API is versioned using the path prefix **/api/v1**. When the API is
updated, the version number will be incremented to **/api/v2**, and the
previous version will be deprecated.

## API Documentation

The API is documented using Swagger. You can access the **Swagger**
documentation at http://127.0.0.1:5000/apidocs.

**Swagger** can be conditionally enabled or disabled using the
**SWAGGER_ENABLED** environment variable.

## Prometheus

**Prometheus** endpoint is available at:

http://localhost:19090/metrics

http://localhost:19090/targets

## Deployment on Kubernetes

Kubernetes deployment files are located in the **.infrastructure/k8s**
directory.

To deploy the **Account** microservice to **Kubernetes**, use the following
commands:

1. **Namespace**: Apply the namespace yaml first. All other resources will be
   created within this namespace (**cba-dev**).

```bash
kubectl apply -f ./.infrastructure/k8s/cba-dev-ns.yml
```

2. **ConfigMap**: Apply the ConfigMap yaml next. The Deployment depends on it.

```bash
kubectl apply -n cba-dev -f ./.infrastructure/k8s/account-srv-cm.yml
```

3. **Secret**: Apply the Secret yaml. The Deployment also depends on it.

```bash
kubectl apply -n cba-dev -f ./.infrastructure/k8s/account-srv-secret.yml
```

4. **Deployment**: Apply the Deployment yaml last. It depends on the Namespace,
   ConfigMap, and Secret.

```bash
kubectl apply -n cba-dev -f ./.infrastructure/k8s/account-srv-deployment.yml
```

5. **Service**: Apply the Service yaml. It depends on the Pods created by the
   Deployment.

```bash
kubectl apply -n cba-dev -f ./.infrastructure/k8s/account-srv-service.yml
```

6. **HPA**: Apply the HPA yaml. It depends on the Deployment.

```bash
kubectl apply -n cba-dev -f ./.infrastructure/k8s/account-srv-hpa.yml
```

Check the pods are running with:

```bash
kubectl get pods -n cba-dev
```

Check the Service is created with:

```bash
kubectl get services -n cba-dev
```

Check the HPA is created with:

```bash
kubectl get hpa -n cba-dev
```
