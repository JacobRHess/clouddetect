# The live loop

The fixture replay (run in CI) proves each detection against a hand-authored
log. The live loop proves it against the real thing: it detonates an actual
attack with [Stratus Red Team](https://github.com/DataDog/stratus-red-team),
pulls the CloudTrail those API calls produced, and replays it through the same
Splunk and OpenSearch the fixtures use.

```
 stratus detonate <technique>      (real attack in a sandbox account)
            │
            ▼
   CloudTrail records the calls
            │  LookupEvents (polled; management events can lag minutes)
            ▼
 normalize → same shape as a fixture
            │
            ▼
 replay through Splunk + OpenSearch ──► did the mapped detection fire?
            │
            ▼
 stratus cleanup <technique>        (tear the attack infra back down)
```

This path is **never run in CI**. It needs AWS credentials and is destructive by
design, so you run it by hand.

## Safety first

- **Use a dedicated sandbox AWS account.** Never point this at production or any
  account with real data. Stratus performs real attacks (disabling CloudTrail,
  creating admin users) and this tool replays real log data.
- Stratus always leaves infrastructure behind until `cleanup` runs. The loop
  cleans up automatically unless you pass `--keep`.
- Costs are small but non-zero (a t-class instance here and there). Tear down.

## Prerequisites

1. A sandbox AWS account, with credentials in the environment (`AWS_PROFILE` or
   `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION`). Stratus needs
   broad permissions to set up and detonate; an isolated sandbox where you hold
   admin is the intended model. The loop itself additionally needs
   `cloudtrail:LookupEvents`.
2. A CloudTrail trail logging management events in that account/region (the
   account-default trail is enough; LookupEvents reads management events even
   without one, with more lag).
3. The [stratus binary](https://github.com/DataDog/stratus-red-team/releases) on
   `PATH`.
4. The local lab up and the live extra installed:

   ```bash
   uv sync --extra dev --extra live
   docker compose -f lab/docker-compose.yml up -d
   export CD_SPLUNK_PASSWORD=clouddetect_dev_2026
   ```

## Running it

```bash
uv run clouddetect detonate --list                       # supported techniques
uv run clouddetect detonate aws.defense-evasion.cloudtrail-stop
```

Example output:

```
technique aws.defense-evasion.cloudtrail-stop -> detection cloudtrail-logging-disabled
pulled 1 real CloudTrail events
  splunk      FIRED
  opensearch  FIRED
detection held on real attacker telemetry
```

Useful flags: `--timeout 1200` (wait longer for laggy management events),
`--keep` (skip cleanup so you can inspect the account), `--region us-east-1`.

## Supported techniques

Only techniques with a matching clouddetect detection are wired up. Others are
rejected with the supported list.

| Stratus technique | Detection it should trip |
|---|---|
| `aws.defense-evasion.cloudtrail-stop` | `cloudtrail-logging-disabled` |
| `aws.defense-evasion.cloudtrail-delete` | `cloudtrail-logging-disabled` |
| `aws.persistence.iam-create-admin-user` | `iam-attach-admin-policy` |

The map lives in `STRATUS_MAP` in `src/clouddetect/live.py`; adding a row there
(plus the CloudTrail event names to poll for) extends the loop to a new
detection.

## Note on CloudTrail latency

CloudTrail management events are not real time; they typically appear within a
few minutes but can take up to ~15. The loop polls until `--timeout`, so a miss
usually means "waited too little," not "detection failed." Raise `--timeout`
before concluding a rule did not fire.
