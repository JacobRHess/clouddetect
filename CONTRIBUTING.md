# Contributing

## Setup

```bash
git clone https://github.com/JacobRHess/clouddetect
cd clouddetect
uv sync --extra dev --frozen
uv run pre-commit install
```

`--frozen` installs exactly what `uv.lock` pins. If you change a dependency in
`pyproject.toml`, regenerate the lockfile with `uv lock` and commit both files
together.

## Gates the CI runs

Run them locally in the same order before pushing:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run bandit -c pyproject.toml -q -r src
uv run pip-audit --skip-editable --ignore-vuln CVE-2025-69872
uv run pytest -q --cov
uv run python -m clouddetect.attackdoc > docs/ATTACK.md        # diff must be empty
uv run clouddetect attack --layer docs/attack-layer.json       # diff must be empty
```

The live replay through Splunk and OpenSearch only happens in CI (and the local
lab), because it needs both engines running. The default `pytest` run deselects
those `replay` tests, so the offline gate stays fast.

## Proving a detection locally

```bash
docker compose -f lab/docker-compose.yml up -d
export CD_SPLUNK_PASSWORD=clouddetect_dev_2026     # PowerShell: $env:CD_SPLUNK_PASSWORD=...
uv run pytest -m replay
uv run clouddetect report --out report.html        # optional: the HTML summary
```

If you already run a native Splunk on this machine, it owns ports 8088/8089 and
the lab container will fail to bind them. Map the lab Splunk to free ports and
point the harness at them:

```bash
# bring the lab Splunk up on alternate host ports, then:
export CD_HEC_PORT=28088
export CD_API_PORT=28089
```

`CD_OS_URL` does the same for OpenSearch if 9200 is taken.

## Adding a detection

1. **Write the Sigma rule** under `rules/cloudtrail/` or `rules/okta/`. Reference
   the technique, give it ATT&CK `tags`, and a `falsepositives` note. It must
   convert to exactly one query on both backends.
2. **Add two fixtures** under `fixtures/`: a JSON array of raw log events that
   must fire the rule (`.alert.json`) and one that must not (`.benign.json`).
   Pick a benign sample that differs on the *discriminating* field, not just any
   unrelated event, so the rule is actually tested.
3. **Add a manifest entry** in `detections.yaml`: `id`, `title`, `logsource`,
   `rule`, `attack`, and the two `fixtures`.
4. If the rule uses a new ATT&CK technique, add its name to `TECHNIQUE_NAMES` in
   `src/clouddetect/attackdoc.py`, then regenerate the docs (commands above).
5. `uv run clouddetect validate`, then prove it with the replay steps above.

## Principles

- Sigma is the single source of truth. A detection that only works on one
  backend is a portability bug, and CI is meant to catch it.
- Every detection ships with the logs that prove it. No fixture, no detection.
