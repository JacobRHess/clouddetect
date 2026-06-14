# clouddetect

Cloud and identity detections, each shipped with the logs that prove it fires.

Most detection content is a wall of rules you have to take on faith. clouddetect
takes the opposite position: every detection here comes with two log fixtures, an
attack sample that must fire it and a benign sample that must not, and CI replays
both through real SIEMs on every push. A rule that matches everything fails the
benign half. A rule that matches nothing fails the attack half. Only rules that
do exactly one job survive.

## How it works

Detections are authored once as [Sigma](https://github.com/SigmaHQ/sigma) rules,
the portable detection standard. From that single source clouddetect converts
each rule to:

- **SPL**, replayed through **Splunk**
- **Lucene/DSL**, replayed through **OpenSearch**

Both backends must agree: the attack fixture fires the rule, the benign fixture
stays silent. If a rule passes in Splunk but not OpenSearch, that is a bug in the
rule's portability, and CI catches it.

```
                 detections.yaml  (single source of truth)
                        │
              rules/**/*.yml  (Sigma)
                  ╱             ╲
        Sigma → SPL          Sigma → Lucene/DSL
            │                       │
      Splunk (CI service)    OpenSearch (CI service)
            │                       │
   index this fixture's     index this fixture's
   events, run the query    events, run the query
            ╲                     ╱
        alert fixture → must fire
        benign fixture → must stay silent
                  (both backends)
```

## Coverage

| Surface | Source | Detections |
|---|---|---|
| AWS control plane | CloudTrail | AdministratorAccess attachment, IAM user added to an admin group, console login profile created, CloudTrail logging disabled, AWS Config disabled, GuardDuty torn down, root account used, KMS key scheduled for deletion |
| Identity | Okta System Log | API token created, MFA factor reset, Super Administrator granted |

The full, always-current list is `docs/ATTACK.md`, generated from the manifest.

Every detection is tagged to the MITRE ATT&CK Cloud matrix; `docs/ATTACK.md` and
the ATT&CK Navigator layer are generated from the manifest, not hand-edited.

## The live loop

Fixtures prove the rules in isolation. The `clouddetect detonate` command closes
the loop end to end: it runs [Stratus Red Team](https://github.com/DataDog/stratus-red-team)
against a dedicated AWS sandbox, pulls the CloudTrail events the attack actually
produced, replays them through the same detections, and shows them fire on real
attacker telemetry rather than a hand-built sample. This path needs AWS
credentials and is never run in CI — see [docs/LIVE-LOOP.md](docs/LIVE-LOOP.md).

```bash
uv sync --extra live
uv run clouddetect detonate --list
uv run clouddetect detonate aws.defense-evasion.cloudtrail-stop
```

## Running it

```bash
uv sync --extra dev
uv run clouddetect list            # every detection and its ATT&CK mapping
uv run clouddetect validate        # rules parse and convert on both backends
docker compose -f lab/docker-compose.yml up -d   # local Splunk + OpenSearch
uv run pytest -m replay            # replay every fixture through both engines
uv run clouddetect report --out report.html
```

## Layout

```
detections.yaml        single source of truth: id, rule, ATT&CK, fixtures
rules/cloudtrail/      Sigma rules for AWS CloudTrail
rules/okta/            Sigma rules for the Okta System Log
fixtures/              alert + benign log samples, one pair per detection
src/clouddetect/       manifest, Sigma converter, engine clients, harness, CLI
lab/                   docker-compose for a local Splunk + OpenSearch
docs/                  generated ATT&CK coverage + the live-loop runbook
```
