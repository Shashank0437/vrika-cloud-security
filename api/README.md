# Description

This repository contains the JSON API and Task Runner components for Prowler, which facilitate a complete backend that interacts with the Prowler SDK and is used by the Prowler UI.

## Vrika findings triage

Triage is an organization-private workflow attached to **tenant + provider +
finding UID**, not a single scan snapshot. It supports Open, Under Review,
Remediating, Risk Accepted and False Positive, one editable 500-character note,
and an audit history. Completed scans mark an observed PASS as Resolved and a
subsequent observed FAIL as Reopened. Repeated or out-of-order tasks cannot
overwrite newer results. Missing findings, scoped-out checks and failed scans
are never treated as proof of resolution.

`manage_triage` permits ordinary status/note changes.
`manage_triage_exceptions` additionally permits Risk Accepted and False Positive.
The upgrade grants both to `admin`, and only ordinary triage to `vrika_member`;
custom roles remain unchanged. Existing users inherit these role updates without
being re-provisioned. Provider-group visibility applies to reads and writes.

Exceptions require explicit mute confirmation and a reason of 3-500 characters.
Status, note, audit event and Mutelist rule are saved atomically; historical
muting and group reaggregation follow through the existing worker tasks.
Provider-ambiguous UIDs and UIDs over the existing Mutelist 255-character limit
are rejected for exceptions instead of muting other providers. **Returning to
Open does not disable the Mutelist rule or unmute historical findings**; manage
that rule separately. Triage never changes raw check results or creates emails,
external tickets or Manual Pass attestations. Clearing a note preserves its
previous text in the organization-private audit history.

The feature is **off by default**. For an approved deployment:

1. Apply migrations through `0100_triage_managed_roles` using the normal admin
   database migration procedure, and deploy the matching Vrika bridge templates.
2. Set `VRIKA_TRIAGE_ENABLED=true` for API and scan/overview workers.
3. Build the UI with `NEXT_PUBLIC_VRIKA_TRIAGE_ENABLED=true` (Docker build arg).
   Do not enable `NEXT_PUBLIC_IS_CLOUD_ENV`; Alerts remains separate.

There is no automatic historical backfill. Existing snapshots show Open/Resolved
until a triage write or a new completed scan initializes persistent state.
Notes/history are available from each finding's action menu, including expanded
groups and resource drawers; read-only users can view them. API writes use
JSON:API `PATCH /findings/{snapshot-id}/triage` with type `finding-triages` and
the snapshot ID as `data.id`, or `/finding-triages/{triage-id}` with its triage ID.
Attributes are `status`, `note`, optional `previous_status` for stale-write
protection, and `confirm_mute`/`reason` for exceptions. Both routes expose
`/notes` and paginated `/history`; individual note PATCH/DELETE routes use the
note ID. UID aliases are accepted only when they identify one visible provider.
Stale edits are rejected with a refresh instruction rather than overwriting newer
triage decisions. Expected API errors cross the UI server-action boundary as
structured results so production rendering does not hide that instruction.

## Executive and full PDF layout

Scan reports use a compact overview with score/resource/priority metrics,
page-width-aware tables, vector severity/outcome charts and two-column compliance
cards. Account identifiers and aliases wrap without being shortened, and custom
tenant logos are retained. Section headings stay with their content and table
headers repeat across page breaks.

This presentation does not change scoring, finding filters, narrative text or
report selection limits. Both variants retain the executive summary, observations,
account metadata, control outcomes, security domains, compliance cards, top risks
and recommendations. The full variant additionally retains the domain appendix,
including its existing limit of 25 checks per domain across up to 15 domains.
The separate compliance-framework PDF generators are unchanged.

## Schedule first-run timing

Saving an advanced schedule does not launch a scan. Daily, weekly and monthly
schedules first run at the next selected time in the configured timezone.
Interval schedules first run at the next selected scan hour, then repeat at the
configured interval. If that time has already passed, the first run waits for the
next occurrence; it is not treated as a missed run to execute immediately.

Changing the cadence or re-enabling a disabled schedule starts a new scheduling
baseline. Saving an unchanged schedule preserves its cadence. The optional
**Launch an initial scan now** action remains separate and does not move the
next scheduled run. Beat's `last_run_at` is initialized as a scheduling baseline;
the displayed last completed scan continues to come from actual scan records.
Existing schedules and completed scans are not rewritten during deployment.

## Scheduled scan report emails

Scheduled scans send report emails only after scan summaries, output processing
and report generation finish. The scheduled email task is a continuation of the
report task, not an independent task launched when scanning ends. Report results
containing errors, or a missing executive report result, block the email.
Integrations and Attack Paths remain independent of email delivery.

Both the executive and full PDF must be readable and have PDF header/end markers
before the notification is submitted. Missing full reports are generated before
sending; generation, file-reading and notification errors fail the email task
rather than silently sending a fallback report. This does not change the completed
scan's status. `accepted` means the Vrika mail service accepted the notification,
not that SMTP delivery has been confirmed. Delivery is not automatically retried.

Manual scans remain opt-in through **Share by email**, with the same attachment
checks. Existing emailed PDFs are not replaced or resent by this change.

## Attack Paths: AWS, GCP and Azure

New scans automatically schedule Attack Paths for AWS, GCP and Azure. Existing
GCP/Azure scans are not backfilled automatically; run a new scan after upgrading
the API and workers. The existing graph database configuration is required.

GCP inventory is restricted to the connected project. IAM collection additionally
reads that project's ancestors and expands only groups referenced by collected
policies. Azure inventory is restricted to the connected subscription; inherited
RBAC comes from assignments returned for that scope, and Microsoft Graph expansion
is restricted to groups referenced by those assignments. Credentials and sovereign
cloud endpoints come from the existing provider connection. Neither integration
grants itself permissions or enables APIs.

| Coverage | GCP | Azure |
|---|---|---|
| Inventory and findings | Compute, buckets, secret metadata, Cloud Run, Functions, GKE clusters/node pools, Cloud SQL, BigQuery datasets | VMs, storage/containers, vaults, App Service/Functions, AKS, SQL servers |
| Permission evidence | Direct and ancestor IAM, referenced predefined/custom role permissions, group memberships, user-managed key metadata | Direct/inherited RBAC, custom role actions and exclusions, transitive group membership, legacy vault policies |
| Candidate escalation/data paths | Token creation, signing, key creation, actAs, policy/role changes, VM/serverless modification, data grants and impersonation chains | Role changes, VM commands/extensions, publishing, AKS admin credential permissions, storage keys/data, vault access and VM-identity chains |
| Network configuration | VPC firewall targets, VM public IPs, forwarding rules, SQL authorized networks, public dataset ACLs | NIC/subnet NSGs, public-IP associations, SQL firewall rules, public blob configuration |
| Restrictions and coverage | Conditional grants, directly attached project deny-policy evidence, per-service collection results | Conditional grants, deny-assignment evidence, separate PIM eligibility, per-service collection results |

There are 34 GCP and 28 Azure predefined queries. These are investigation paths,
**not proof of exploitability or AWS feature parity**. Grant analysis is conservative:
conditional grants are excluded from unconditional candidate paths; Azure
Actions/NotActions and DataActions/NotDataActions are evaluated per permission
block, and PIM eligibility never creates an active assignment edge.

Predefined GCP/Azure queries return the selected paths together with linked,
unmuted failed findings and their `HAS_FINDING` edges, so the graph and resource
details can display Related Findings. Paths without findings remain visible.
This query enrichment uses the existing graph and requires no rescan. Custom
queries still return only what their Cypher explicitly selects.

Full effective-permission resolution is not implemented. Deny-policy evidence is
not automatically subtracted from every allow path; GCP ancestor denies, principal
access boundaries, OAuth scope enforcement, domain/federated principal expansion,
and pod-level GKE/AKS access are not resolved. GCP membership paths display up to
eight group hops. Azure ABAC, PIM activation requirements, and directory-role
privilege escalation are not resolved. Public IP/firewall combinations are
**exposure candidates**: rule priority, routing, hierarchical policies, destination
matching and runtime service state may block access. No `Internet -> CAN_ACCESS`
edges are synthesized from these candidates.

### GCP read access and enabled APIs

Grant read permissions to the identity used by the connected provider, not to the
Neo4j server. Enabling an API and granting IAM permissions are separate steps.
The API's reported consumer may be the scanned project or its credential/quota
project; enable it in the project identified by the error. `serviceusage.services.use`
may also be required on the quota project. No Secret Accessor, Storage Object
Viewer, token-creation or administrator role is needed merely to collect metadata.

| Collector | API | Relevant read permissions/access |
|---|---|---|
| Project and ancestor IAM | `cloudresourcemanager.googleapis.com` | `resourcemanager.projects.get`, `resourcemanager.projects.getIamPolicy`; ancestor folder/organization get and getIamPolicy access where applicable |
| Resource IAM | `cloudasset.googleapis.com` | `cloudasset.assets.searchAllIamPolicies` on the scanned project; `iam.roles.get` for complete permission information |
| Accounts, keys and roles | `iam.googleapis.com` | `iam.serviceAccounts.list`, `iam.serviceAccountKeys.list`, `iam.roles.get` |
| Project deny policies | `iam.googleapis.com` | `iam.denypolicies.list`, `iam.denypolicies.get` |
| Compute/network | `compute.googleapis.com` | `compute.instances.list`, `compute.firewalls.list`, `compute.forwardingRules.list`, `compute.globalForwardingRules.list` |
| Storage metadata | `storage.googleapis.com` | `storage.buckets.list` (including bucket metadata) |
| Secret metadata | `secretmanager.googleapis.com` | `secretmanager.secrets.list` |
| Cloud Run | `run.googleapis.com` | `run.services.list` |
| Cloud Functions | `cloudfunctions.googleapis.com` | `cloudfunctions.functions.list` |
| GKE | `container.googleapis.com` | `container.clusters.list` |
| Cloud SQL | `sqladmin.googleapis.com` | `cloudsql.instances.list` |
| BigQuery dataset metadata | `bigquery.googleapis.com` | `bigquery.datasets.get` for visible datasets; dataset ACL visibility |
| Referenced groups | `cloudidentity.googleapis.com` | Cloud Identity group lookup and membership-read authorization; Google Workspace/Cloud Identity directory authorization may be required in addition to project IAM |

An API-disabled error can mask a subsequent permission denial. Re-run after
enabling APIs to discover the next missing permission; a single scan cannot prove
that all unexercised resource-level reads will be authorized.

### Azure read access and licensing

Subscription Reader normally covers the management-plane inventory. Custom roles
must cover the relevant Compute, Network, Storage, KeyVault, Web,
ContainerService, Sql and Authorization read operations, including role
definitions/assignments, deny assignments and eligibility schedule instances.
Ancestor assignment visibility depends on the identity's permitted scopes.
Group expansion needs Microsoft Graph group-membership read authorization
(typically application `GroupMember.Read.All` with administrator consent;
hidden memberships can require additional authorization).
PIM eligibility APIs can additionally require an Entra ID P2 or ID Governance
license; extra RBAC permission alone does not resolve a licensing error.

No secret values, storage keys, tokens, database rows, application settings,
private key material or Kubernetes administrator credentials are fetched.
Queries about those privileges analyse role definitions, not the protected data.

Core credential/project/subscription errors fail ingestion. Optional service
errors remain visible in scan details; if every service fails, the graph is not
published. Services outside the collected inventory do not have findings linked.
The provider's **Collection Coverage and Permission Errors** query exposes
collection failures in the graph; an empty risk query is not evidence of safety
when its prerequisite collection failed. Project IAM runs independently from
Cloud Asset IAM search so a disabled Cloud Asset API does not erase project grants.
AWS's existing ingestion and query catalog are unchanged.

Focused backend tests live in `api/tests/attack_paths`. Run with
`PYTHONPATH=src/backend DJANGO_SETTINGS_MODULE=config.django.testing`.
Graph integration tests require an **empty disposable Neo4j instance**:
set `ATTACK_PATHS_TEST_NEO4J_URI` and `ATTACK_PATHS_TEST_ALLOW_RESET=1` before
running `pytest tests/attack_paths`. They remove fixture nodes after each test;
never point this test suite at a production graph database.

## Backend components
The Prowler API is composed of the following components:

- The JSON API, which is an API built with Django Rest Framework.
- The Celery worker, which is responsible for executing the background tasks that are defined in the JSON API.
- The PostgreSQL database, which is used to store the data.
- The Valkey database, which is an in-memory database which is used as a message broker for the Celery workers.

### Note about Valkey

[Valkey](https://valkey.io/) is an open source (BSD) high performance key/value datastore.

Valkey exposes a Redis 7.2 compliant API. Any service that exposes the Redis API can be used with Prowler API.

## Modify environment variables

Under the root path of the project, you can find a file called `.env`. This file shows all the environment variables that the project uses. You should review it and set the values for the variables you want to change.

If you don’t set `DJANGO_TOKEN_SIGNING_KEY` or `DJANGO_TOKEN_VERIFYING_KEY`, the API will generate them at `~/.config/prowler-api/` with `0600` and `0644` permissions; back up these files to persist identity across redeploys.

**Important note**: Every Prowler version (or repository branches and tags) could have different variables set in its `.env` file. Please use the `.env` file that corresponds with each version.

### Local deployment
Keep in mind if you export the `.env` file to use it with local deployment that you will have to do it within the context of the virtual environment, not before. Otherwise, variables will not be loaded properly.

To do this, you can run:

```console
set -a
source .env
```

## 🚀 Production deployment
### Docker deployment

This method requires `docker` and `docker compose`.

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

#### Build the base image

```console
docker compose --profile prod build
```

#### Run the production service

This command will start the Django production server and the Celery worker and also the Valkey and PostgreSQL databases.

```console
docker compose --profile prod up -d
```

You can access the server in `http://localhost:8080`.

> **NOTE:** notice how the port is different. When developing using docker, the port will be `8080` to prevent conflicts.

#### View the Production Server Logs

To view the logs for any component (e.g., Django, Celery worker), you can use the following command with a wildcard. This command will follow logs for any container that matches the specified pattern:

```console
docker logs -f $(docker ps --format "{{.Names}}" | grep 'api-')

## Local deployment

To use this method, you'll need to set up a Python virtual environment (version ">=3.11,<3.13") and keep dependencies updated. Additionally, ensure that `uv` and `docker compose` are installed.

### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```
### Install all dependencies with uv

```console
uv sync
```

## Start the PostgreSQL Database and Valkey

The PostgreSQL database (version 16.3) and Valkey (version 7) are required for the development environment. To make development easier, we have provided a `docker-compose` file that will start these components for you.

**Note:** Make sure to use the specified versions, as there are features in our setup that may not be compatible with older versions of PostgreSQL and Valkey.


```console
docker compose up postgres valkey -d
```

## Deploy Django and the Celery worker

### Run migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
cd src/backend
python manage.py migrate --database admin
```

### Run the Celery worker

```console
cd src/backend
python -m celery -A config.celery worker -l info -E
```

### Run the Django server with Gunicorn

```console
cd src/backend
gunicorn -c config/guniconf.py config.wsgi:application
```

> By default, the Gunicorn server will try to use as many workers as your machine can handle. You can manually change that in the `src/backend/config/guniconf.py` file.

## 🧪 Development guide

### Local deployment

To use this method, you'll need to set up a Python virtual environment (version ">=3.11,<3.13") and keep dependencies updated. Additionally, ensure that `uv` and `docker compose` are installed.

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

#### Start the PostgreSQL Database and Valkey

The PostgreSQL database (version 16.3) and Valkey (version 7) are required for the development environment. To make development easier, we have provided a `docker-compose` file that will start these components for you.

**Note:** Make sure to use the specified versions, as there are features in our setup that may not be compatible with older versions of PostgreSQL and Valkey.


```console
docker compose up postgres valkey -d
```

#### Install the Python dependencies

> You must have uv installed

```console
uv sync
```

#### Apply migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
cd src/backend
python manage.py migrate --database admin
```

#### Run the Django development server

```console
cd src/backend
python manage.py runserver
```

You can access the server in `http://localhost:8000`.
All changes in the code will be automatically reloaded in the server.

#### Run the Celery worker

```console
python -m celery -A config.celery worker -l info -E
```

The Celery worker does not detect and reload changes in the code, so you need to restart it manually when you make changes.

### Makefile-Assisted Local Deployment

This method is an additional local development workflow. It does not replace the manual local deployment or the Docker deployment described in this guide.

PostgreSQL, Valkey, and Neo4j run with Docker Compose, while Django and the Celery worker run natively through `uv`. Additionally, this workflow creates a `tmux` session with panes for the API, worker, and PostgreSQL logs.

Before using this method, ensure `docker compose`, `tmux`, and `uv` are installed.

This workflow is designed for macOS and should also work on Linux when Docker, `tmux`, and `uv` are available. Windows requires script changes before it can be supported.

From the repository root, run:

```console
make dev
```

The API will be available at:

```console
http://localhost:8080/api/v1
```

Use these commands to manage the local stack:

```console
make dev-setup   # Bootstrap dependencies, migrations, and fixtures
make dev-attach  # Attach to the tmux session
make dev-launch  # Start the stack on fixed ports and attach
make dev-stop    # Stop the tmux session and containers
make dev-clean   # Remove stopped development containers
make dev-wipe    # Stop everything and delete local development data
make dev-status  # Show development container status
```

This workflow does not start the UI. Start it separately from the `ui/` directory when needed.

### Docker deployment

This method requires `docker` and `docker compose`.

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

#### Build the base image

```console
docker compose --profile dev build
```

#### Run the development service

This command will start the Django development server and the Celery worker and also the Valkey and PostgreSQL databases.

```console
docker compose --profile dev up -d
```

You can access the server in `http://localhost:8080`.
All changes in the code will be automatically reloaded in the server.

> **NOTE:** notice how the port is different. When developing using docker, the port will be `8080` to prevent conflicts.

#### View the development server logs

To view the logs for any component (e.g., Django, Celery worker), you can use the following command with a wildcard. This command will follow logs for any container that matches the specified pattern:

```console
docker logs -f $(docker ps --format "{{.Names}}" | grep 'api-')
```

### Applying migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
cd src/backend
uv run python manage.py migrate --database admin
```

### Apply fixtures

Fixtures are used to populate the database with initial development data.

```console
cd src/backend
uv run python manage.py loaddata api/fixtures/0_dev_users.json --database admin
```

> The default credentials are `dev@prowler.com:Thisisapassword123@` or `dev2@prowler.com:Thisisapassword123@`

### Run tests

Note that the tests will fail if you use the same `.env` file as the development environment.

For best results, run in a new shell with no environment variables set.

```console
cd src/backend
uv run pytest
```

## Custom commands

Django provides a way to create custom commands that can be run from the command line.

> These commands can be found in: ```prowler/api/src/backend/api/management/commands```

To run a custom command, you need to be in the `prowler/api/src/backend` directory and run:

```console
uv run python manage.py <command_name>
```

### Generate dummy data

```console
python manage.py findings --tenant
<TENANT_ID> --findings <NUM_FINDINGS> --re
sources <NUM_RESOURCES> --batch <TRANSACTION_BATCH_SIZE> --alias <ALIAS>
```

This command creates, for a given tenant, a provider, scan and a set of findings and resources related altogether.

> Scan progress and state are updated in real time.
> - 0-33%: Create resources.
> - 33-66%: Create findings.
> - 66%: Create resource-finding mapping.
>
> The last step is required to access the findings details, since the UI needs that to print all the information.

#### Example

```console
~/backend $ uv run python manage.py findings --tenant
fffb1893-3fc7-4623-a5d9-fae47da1c528 --findings 25000 --re
sources 1000 --batch 5000 --alias test-script

Starting data population
	Tenant: fffb1893-3fc7-4623-a5d9-fae47da1c528
	Alias: test-script
	Resources: 1000
	Findings: 25000
	Batch size: 5000


Creating resources...
100%|███████████████████████| 1/1 [00:00<00:00,  7.72it/s]
Resources created successfully.


Creating findings...
100%|███████████████████████| 5/5 [00:05<00:00,  1.09s/it]
Findings created successfully.


Creating resource-finding mappings...
100%|███████████████████████| 5/5 [00:02<00:00,  1.81it/s]
Resource-finding mappings created successfully.


Successfully populated test data.
```
