# Account microservice

![Build Status](https://github.com/hokushin118/account-service/actions/workflows/ci.yml/badge.svg)

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

I've been
using [Red Hat Enterprise Linux for Workstations](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux/workstations)
as my development machine, but the project should run on any operating system.
The project uses [Gunicorn](https://gunicorn.org) for local
development. [Gunicorn](https://gunicorn.org) is a WSGI HTTP server designed
specifically for Unix-like systems (Linux, macOS, etc.) and you cannot
directly use [Gunicorn](https://gunicorn.org) on Windows. Therefore, you'll
need to
use [Docker](https://docs.docker.com/desktop/setup/install/windows-install/) to
run the application locally on Windows.

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

5. Deploy infrastructure services with **Docker Compose**:

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

1. Make sure you have deployed infrastructure services with **Docker Compose**:

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

## Deployment on OpenShift using Tekton

[Tekton](https://tekton.dev) is a cloud-native solution for building CI/CD
systems. It consists of [Tekton](https://tekton.dev) Pipelines, which provides
the building blocks, and of supporting components, such as Tekton CLI and
Tekton Catalog, that make Tekton a complete ecosystem. For more information,
see the [Tekton documentation](https://tekton.dev/docs/).

You would need to have **OpenShift CLI** (oc) installed on your machine. You
can download it
from [here](https://access.redhat.com/downloads/content/290/ver=4.17/rhel---9/4.17.16/x86_64/product-software).

Verify the availability of the OpenShift CLI using the following command:

```bash
oc version
```

The [Tekton](https://tekton.dev) pipeline deployment files for **OpenShift**
are located in the **.infrastructure/openshift/tekton** directory.

1. Login to **OpenShift** cluster, using the following command:

```bash
oc login --token=<token> --server=https://api.,,.p1.openshiftapps.com:6443
```

2. Install [Tekton Pipeline](https://github.com/tektoncd/pipeline/releases)
   on **OpenShift** using the following command:

```bash
oc apply -f https://storage.googleapis.com/tekton-releases/pipeline/previous/v0.68.0/release.yaml
```

3. [Download](https://github.com/tektoncd/cli/releases) and install [Tekton
   CLI](https://tekton.dev/docs/cli) on your machine. For example, to download
   and install **Tekton CLI** on **RHEL 9**, use the following commands:

```bash
rpm -Uvh https://github.com/tektoncd/cli/releases/download/v0.37.1/tektoncd-cli-0.37.1_Linux-64bit.rpm
```

or

```bash
curl -LO https://github.com/tektoncd/cli/releases/download/v0.37.1/tkn_0.37.1_Linux_x86_64.tar.gz
sudo tar xvzf tkn_0.37.1_Linux_x86_64.tar.gz -C /usr/local/bin/ tkn
```

After installation (using either method), verify that Tekton is installed
correctly, using the following command:

```bash
tkn version
```

4. To create a workspace for pipeline on **OpenShift**, use the following
   commands:

```bash
oc create -f .infrastructure/openshift/cba-pipeline-pvc.yml
```

5. Apply the Secret yaml if you are using a private repository.

```bash
oc apply -f .infrastructure/openshift/cba-pipeline-secret.yml
```

6. To create custom [Tekton](https://tekton.dev) tasks for pipeline on *
   *OpenShift**, use the following commands:

```bash
oc apply -f .infrastructure/openshift/tekton/tasks/run-cleanup-workspace.yml 
oc apply -f .infrastructure/openshift/tekton/tasks/run-flake8-lint.yml 
oc apply -f .infrastructure/openshift/tekton/tasks/run-nose-tests.yml 
```

Apply the run-github-clone-w-token.yml if you are using a private repository.

```bash
oc apply -f .infrastructure/openshift/tekton/tasks/run-github-clone-w-token.yml 
```

To verify the created custom tasks, using the following command:

```bash
oc get tasks
```

7. The **clone** task requires the **git-clone**, the **build** task
   requires **buildah** and the **deploy** task requires the
   ""openshift-client"" tasks from the **Tekton Hub**, use the following
   commands to install them:

```bash
tkn hub install task git-clone
tkn hub install task buildah
tkn hub install task openshift-client
```

Make sure that the **git-clone**, **buildah** and **openshift-client** tasks
are available in the **OpenShift** using the following command:

```bash
oc get clustertask
```

8. To create [Tekton](https://tekton.dev) pipeline on **OpenShift**, use the
   following command:

```bash
oc apply -f .infrastructure/openshift/tekton/cba-pipeline.yml
```

9. To start pipeline on **OpenShift**, use the following command:

```bash
tkn pipeline start cba-pipeline \
            -p repo-url=<GITHUB_REPO_URL> \
            -p branch=<BRANCH> \
            -p build-image=<DOCKER_IMAGE> \
            -p deploy-enabled=<DEPLOY_ENABLED> \
            -w name=<WORKSPAVCE_NAME>,claimName=<PVC_CLAIM_NAME> \
            -s pipeline \
            --showlog
```

- **GITHUB_REPO_URL** - URL of the GitHub repository
- **BRANCH** - name of the branch
- **DOCKER_IMAGE** - docker image with tag and registry, for example: `quay.
  io/username/cba:latest`
- **DEPLOY_ENABLED** - Enable/disable deployment step, for example: `true`
- **WORKSPACE_NAME** - name of the workspace specified in the pipeline yaml
  file, for example: `cba-pipeline-pvc`
- **PVC_CLAIM_NAME** - name of the PVC claim created for pipeline, for
  example: `cba-pipeline-pvc`

For example:

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

To make the pipeline ran successfully, run the following command:

```bash
tkn pipelinerun ls
```

You can check the logs of the last pipeline run with:

```bash
tkn pipelinerun logs --last
```
