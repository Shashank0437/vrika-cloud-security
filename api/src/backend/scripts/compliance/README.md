# DPDPA Cloud Security Baseline

Framework key: `dpdpa_cloud_security_1.0`. Providers: AWS, Azure and GCP.
Version `1.0` is the Vrika catalog version, not a legislative version.

This catalog assesses cloud-security readiness against the enumerated provisions
below. It is not the full DPDPA, a legal opinion, or a certification. Its 24 entries
include 9 partially automated entries and 15 manual entries. The 43 distinct
provider/check mappings are verified against the SDK pinned in `api/uv.lock`.
They do not cover every cloud service, resource, application or personal-data flow.

## Sources and commencement

Source text reviewed on 2026-10-26:

- [DPDP Act, 2023, Act No. 22 of 2023](https://egazette.gov.in/WriteReadData/2023/248045.pdf),
  particularly sections 8, 10, 12 and 16.
- [Final DPDP Rules, 2025, G.S.R. 846(E)](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf),
  English text from PDF page 24. This is the November notification, not the January draft.

Under rule 1, rule 4 commences one year after Gazette publication; rules 5-16
commence eighteen months after publication. Before commencement, interpret these
entries as readiness checks, not findings of a currently breached legal duty.
Confirm the Act's separate commencement notifications, subsequent amendments,
Government orders, exemptions and applicability with a qualified reviewer.
The catalog does not automatically track legal changes or determine applicability.

Descriptions are assessment summaries, not verbatim legal text. The `SourceClauses`,
`LegalReference`, `Applicability`, `Commencement`, `Coverage` and `EvidenceLimitations`
attributes preserve the source mapping and its limits in the universal schema.

## Coverage matrix

IDs below are suffixes of `VRIKA-DPDPA-CS-`.

| Entries | Cloud-security assessment | Source | Evidence |
| --- | --- | --- | --- |
| 03, 06, 07, 10 | Transport/storage encryption, key protection, masking/tokenization alternatives and coverage | Rule 6(1)(a) | Configuration checks plus manual assurance |
| 01, 02, 07, 08 | Privileged access, storage exposure, key access, network restrictions | Rule 6(1)(b) | Partial configuration evidence |
| 04, 09, 11 | Logging, detection, review, investigation and remediation | Rule 6(1)(c) | Configuration checks plus manual operations |
| 05, 07, 12 | Backups, key recovery, restoration and continued processing | Rule 6(1)(d) | Configuration checks plus manual recovery evidence |
| 13 | Security-evidence retention | Rule 6(1)(e) | Manual |
| 14 | Processor contracts and shared responsibility | Act 8(1)-(2); rule 6(1)(f) | Manual |
| 15 | Effective technical and organizational safeguards | Act 8(4)-(5); rule 6(1)(g) | Manual |
| 16, 17 | Data Principal and Board breach notifications | Act 8(6); rule 7 | Manual |
| 18 | Processing data, traffic data and log retention/erasure | Rule 8(3) | Manual |
| 19 | Cloud/processor erasure and applicable inactivity notices | Act 8(7)-(8), 12(3); rules 8(1)-(2), Third Schedule | Manual |
| 20, 21 | SDF impact assessments, audits, reporting and technical due diligence | Act 10(2); rules 13(1)-(3) | Conditional manual |
| 22 | Applicable international-transfer and SDF data restrictions | Act 16; rules 13(4)-(5), 15 | Conditional manual |
| 23 | Consent Manager platform safeguards, unreadability, records, certification and audits | Rule 4; First Schedule Part A 9, Part B 2-4, 6-7, 12 | Conditional manual |
| 24 | Security and related standards for specified State/research processing | Rules 5, 16; Second Schedule | Conditional manual |

Consent collection, parental verification, general notices, grievance processes,
Board administration and penalties are outside this cloud-security catalog.
Related manual obligations are included only to make the security, incident,
retention, processor and transfer assessment boundaries explicit. Conditional
entries do not imply that the customer is an SDF or registered Consent Manager.

## Interpretation

- `Coverage: Partial` describes evidence coverage, not a new finding status.
  Existing Prowler PASS/FAIL/MANUAL behavior is unchanged.
- At-rest entry 06 has no GCP mapping and is MANUAL for GCP. Requiring a
  customer-managed key solely to produce a check result would overstate the law.
  The deprecated S3 default-encryption check is deliberately excluded.
- A FAIL indicates a configured baseline check failed, not a conclusive legal
  violation. Specific cloud products and configurations are implementation choices.
- A PASS is not proof that every resource was evaluated. The current API roll-up
  can mark mapped requirements PASS when they have no failing findings, including
  when mapped checks return no results. Review errors, permissions and scan scope.
- Muted findings are excluded by the existing API aggregation. Manual and
  conditional entries remain in its denominator; there is no N/A or manual-pass
  workflow added here. With all mapped entries passing, the current rounded score
  is 38% for AWS/Azure (9/24) and 33% for GCP (8/24), not legal compliance.
- One-year security/processing retention is not established by generic 90-day
  checks. Third Schedule inactivity periods are not universal lifecycle settings.
  No data deletion, bucket lifecycle or region restriction is applied by this work.
- Do not treat every region outside India as prohibited. Transfer restrictions
  depend on applicable notifications, orders, sectoral law and data designations.

## Installation and deployment

The API Dockerfile runs `scripts/install_compliance.py` after copying the backend.
It validates the actual SDK schema and metadata IDs, rejects duplicate requirement
IDs/checks and conflicting files, installs the JSON under the SDK's `compliance/`
directory, and verifies discovery for all three providers. The Vrika overlay uses
the same image for API, worker and worker-beat, so no separate UI registration is
needed. Existing compliance views use the standard framework and requirement data.

Build and deploy from the repository root on the deployment host:

```sh
docker build -t prowlercloud/prowler-api:local -f api/Dockerfile api
docker compose -f docker-compose.yml -f docker-compose.vrika.yml up -d --no-deps --force-recreate api worker worker-beat
```

Restarting refreshes process-local framework caches. Run a new scan with the
framework selected, or an unrestricted compliance scan, to generate its summaries.
Existing scan records are not backfilled automatically. No scan is launched by
installation. For a non-Docker API development environment, after installing its
locked dependencies, run `uv run python src/backend/scripts/install_compliance.py`
from `api/`, then restart the API/workers. Rebuild the image for catalog updates;
the installer intentionally refuses to overwrite a different existing catalog.

## Validation

From the repository root, using the API's Python environment for SDK tests:

```sh
api/.venv/bin/python -m unittest discover -s api/src/backend/scripts -p 'test_install_compliance.py' -v
```

The lightweight guards also run with `python3` without Django or cloud credentials;
the SDK integration test is explicitly skipped if Prowler is unavailable. The image
build independently requires successful schema, check-ID and discovery validation.
Manual-review entries cannot be completed through this installer; an evidence and
approval workflow is a separate feature.