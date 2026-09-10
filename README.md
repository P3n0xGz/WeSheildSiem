# WeSheildSiem

A learning-oriented SIEM built from scratch in Python. **v1 scope: log ingestion +
normalization** — collect logs from syslog / files / HTTP, parse and enrich them, normalize
to the Elastic Common Schema (ECS), and store them searchable in OpenSearch. Malformed
events are dead-lettered, never dropped.

- **Design & architecture:** [PLAN.md](PLAN.md)
- **How to implement it yourself, step by step:** [BUILD_GUIDE.md](BUILD_GUIDE.md)

## Status

Skeleton only. Every file under `src/` is currently empty — follow `BUILD_GUIDE.md` to fill
them in, in order, starting with `src/siem/schema.py`.

## Quickstart (once code exists)

```bash
# 1. Dependencies (needs uv: https://docs.astral.sh/uv/)
uv sync --extra dev

# 2. Infra: OpenSearch + Dashboards + Redis
docker compose up -d

# 3. Create index template, data stream, ISM policy
uv run siem bootstrap-opensearch

# 4. Validate config
uv run siem check-config config/pipeline.yml

# 5. Run inputs + pipeline workers
uv run siem run

# 6. In another terminal, replay sample logs
uv run python tools/loggen.py --source sshd --transport syslog-udp --eps 50

# 7. Look at the data
curl 'localhost:9200/logs-*/_search?size=1&pretty'
open http://localhost:5601   # Dashboards -> Discover -> logs-*
```

## Layout

```
config/pipeline.yml          pipeline config (inputs, routing, output, retention)
templates/                   OpenSearch index template + ISM retention policy
src/siem/schema.py           ECS event model + raw envelope        <- start here
src/siem/config.py           config loader/validator
src/siem/queue/streams.py    Redis Streams buffer
src/siem/inputs/             syslog / file tail / HTTP collectors
src/siem/parsers/            parser framework + builtin parsers
src/siem/enrich/             GeoIP + asset enrichment
src/siem/output/             OpenSearch bulk indexer + bootstrap + dead-letter
src/siem/pipeline/worker.py  consume -> parse -> enrich -> normalize -> output
src/siem/cli.py              `siem` command
tools/loggen.py              sample log replayer
tests/                       parser unit tests + integration test
```
