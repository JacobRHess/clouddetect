# Security

## Scope

clouddetect is a detection-engineering project. It ships Sigma rules, synthetic
log fixtures, and a harness that replays those fixtures through Splunk and
OpenSearch. It does not run in production and does not handle real customer
data; every fixture in this repo is hand-authored or generated, never captured
from a real tenant.

## Reporting

Found something wrong with a detection (a false positive, a trivial bypass, a
mislabeled ATT&CK technique) or with the harness itself? Open an issue, or for
anything sensitive email the address in the repo profile.

## Handling of credentials

- The local lab (`lab/docker-compose.yml`) and the CI `validate` job use
  throwaway, in-repo development passwords for Splunk and OpenSearch. They are
  not secrets; they guard ephemeral containers that never leave the runner.
- The live emulation loop (`clouddetect detonate`) reads AWS credentials from
  the standard environment / profile chain. It is intended to run only against
  a dedicated sandbox account and is never exercised in CI.

## Known advisories

Dependency advisories that CI deliberately tolerates, with the reason the
vulnerable path is unreachable here, are listed inline in the `pip-audit` step
of `.github/workflows/ci.yml`.
