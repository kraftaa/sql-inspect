# sql-inspect

Static SQL analysis for reliability and cost risk.

## Example

Input SQL:

```sql
SELECT
  c.customer_id,
  SUM(o.amount) AS revenue
FROM customers c
JOIN orders o
  ON c.id = o.customer_id
GROUP BY c.customer_id
```

Command:

```bash
cargo run -- lineage examples/revenue.sql
```

Output:

```text
examples/revenue.sql
Projections:
revenue
 └─ SUM(orders.amount)
o.customer_id
 └─ orders.customer_id
```

## Why This Exists

SQL pipelines grow quickly and are hard to review.

When a metric looks wrong, teams need to:

- trace where output columns come from
- catch risky query patterns before they hit production
- understand query intent quickly

`sql-inspect` helps with deterministic checks and optional LLM explanations.

## Features

| Feature | Description |
|---|---|
| Static SQL checks | Detect risky patterns (`SELECT *`, possible Cartesian joins, wildcard `LIKE`, etc.) |
| Column lineage | Trace projection, filter, and join lineage |
| Query explanation | Summarize purpose, tables, and aggregations |
| Table extraction | List tables used by a query |
| Folder scanning | Analyze a directory of SQL files |
| Rule controls | Disable rules or override severity by `rule_id` |
| Athena mode | Extra heuristics for partition/cost patterns |
| CI thresholds | Fail on `low|medium|high` severity |

## Detect Risky SQL Patterns

Example query:

```sql
SELECT *
FROM orders o
JOIN customers c
```

Command:

```bash
cargo run -- --file examples/bad_join.sql --static-only
```

Expected findings include:

- `SELECT *`
- possible Cartesian join (`JOIN` without `ON/USING`)

Example subquery pattern:

```bash
cargo run -- --file examples/subquery.sql --static-only
```

Expected suggestion includes:

- consider replacing `IN (SELECT ...)` with `JOIN` or `EXISTS`

## How Is This Different From dbt?

dbt builds and runs transformation pipelines.

`sql-inspect` analyzes SQL itself:

- detect risky query patterns
- trace lineage in query text
- explain query logic

They complement each other: dbt for orchestration/modeling, `sql-inspect` for query inspection.

## Installation

```bash
cargo build
```

## Distribution

### GitHub Releases (prebuilt binaries)

Tagging `v*` triggers `.github/workflows/release.yml` and publishes:

- `sql-inspect-macos-aarch64.tar.gz`
- `sql-inspect-linux-x86_64.tar.gz`
- `SHA256SUMS`

Create a release tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Homebrew tap

Use the formula template at:

- `packaging/homebrew/sql-inspect.rb`

For each release:

1. Set `version` (without `v`).
2. Fill `__SHA256_MACOS_AARCH64__` and `__SHA256_LINUX_X86_64__` from `SHA256SUMS`.
3. Commit the formula in your tap repo (for example `kraftaa/homebrew-tap`) as `Formula/sql-inspect.rb`.
4. Users install with:

```bash
brew install kraftaa/tap/sql-inspect
```

## Usage

### Subcommands

```bash
cargo run -- lineage <file.sql>
cargo run -- risk <file.sql>
cargo run -- guard <file.sql> --max-risk high --deny-rule CROSS_JOIN
cargo run -- simulate <file.sql> --limit 100
cargo run -- tables <file.sql>
cargo run -- explain <file.sql>
cargo run -- analyze <dir> --glob "*.sql"
cargo run -- analyze <dir> --glob "*.sql" --changed-only
cargo run -- pr-review --base main --head HEAD --dir models --glob "*.sql"
```

### PR review mode

```bash
cargo run -- pr-review --base main --head HEAD --dir models --glob "*.sql"
```

Example output:

```text
6 changed SQL files
2 new HIGH-risk queries
1 query lost partition filter
1 ORDER BY without LIMIT regressions
1 possible join amplification regressions
```

### Query Risk Scanner

```bash
cargo run -- risk examples/bad_join.sql
cargo run -- risk examples/bad_join.sql --scan-tb 2.3
cargo run -- risk examples/bad_join.sql --scan-bytes 2300000000000
```

Example output:

```text
examples/bad_join.sql
Risk score: HIGH

Reasons:
- select star: SELECT *
- missing where: No WHERE clause

Estimated scan: 2.30 TB
```

Use one of:

- `--scan-tb <value>` for TB units directly
- `--scan-bytes <value>` to auto-convert bytes to TB
- `--athena-query-execution-id <id>` to fetch `DataScannedInBytes` from Athena via `aws` CLI
- `--athena-region <region>` optional region override for Athena lookup
- `--stats-file <path.json>` to estimate scan bytes from table-level stats

Example `stats.json`:

```json
{
  "tables": {
    "orders": { "bytes": 1000000000000 },
    "customers": 200000000000
  }
}
```

### Block dangerous queries

```bash
cargo run -- guard examples/bad_join.sql --max-risk high --deny-rule CROSS_JOIN --deny-rule FULL_TABLE_SCAN_LIKELY
```

Exit code is `1` when blocked, so this works directly in CI.

### Simulate safer preview query

```bash
cargo run -- simulate examples/query.sql --limit 100
```

### Main Analyze Command (LLM + static)

Provide one of:

- `--sql "<query>"`
- `--file <path>`
- `--dir <path>`

Optional:

- `--provider openai|bedrock|local`
- `--dialect generic|athena`
- `--static-only`
- `--fail-on low|medium|high`
- `--glob "*.sql"`
- `--config sql-inspect.toml`
- `--json`

OpenAI example:

```bash
export OPENAI_API_KEY="..."
export OPENAI_MODEL="gpt-4.1-mini"
cargo run -- --provider openai --file examples/query.sql
```

Bedrock example:

```bash
export AWS_REGION="us-east-1"
export BEDROCK_MODEL_ID="anthropic.claude-3-5-sonnet-20241022-v2:0"
cargo run -- --provider bedrock --file examples/query.sql
```

Local OpenAI-compatible server example:

```bash
export LOCAL_LLM_BASE_URL="http://127.0.0.1:8080"
export LOCAL_LLM_MODEL="llama_instruct.gguf"
cargo run -- --provider local --file examples/query.sql --json
```

## Config

Create `sql-inspect.toml`:

```toml
dialect = "athena"
fail_on = "high"
glob = "*.sql"
suggest_limit_for_exploratory = true
static_only = false

[rules.SELECT_STAR]
enabled = true
severity = "high"

[rules.MISSING_WHERE]
enabled = true
severity = "medium"
```

Rule controls:

- `enabled = false` disables a finding by `rule_id`
- `severity = "low|medium|high"` overrides severity

Example:

```toml
[rules.SELECT_STAR]
enabled = false

[rules.MISSING_WHERE]
severity = "low"
```

## CI Usage

Fail a build when risky SQL is found:

```bash
cargo run -- --dir models --dialect athena --fail-on high
```

Or subcommand mode:

```bash
cargo run -- analyze models --glob "*.sql"
cargo run -- analyze models --glob "*.sql" --changed-only
```

### Inline rule suppression

Add suppression comments directly in SQL when needed:

```sql
-- sql-inspect: disable=SELECT_STAR,MISSING_WHERE
SELECT * FROM some_small_reference_table
```

Suppression applies to matching `rule_id` values for that file.

## Examples Folder

Ready-to-run examples:

- `examples/query.sql`
- `examples/revenue.sql`
- `examples/bad_join.sql`
- `examples/subquery.sql`
- `examples/silver_proposal_attachments.sql`

## Project Layout

```text
sql-inspect/
  Cargo.toml
  src/
    main.rs
    analyzer.rs
    insights.rs
    config.rs
    prompt.rs
    providers/
      openai.rs
      bedrock.rs
      local.rs
  examples/
```

## Troubleshooting

- missing env vars: set required provider vars
- unexpected model JSON shape: run with `--json` and inspect response
- no secrets in repo: `.env` and `.env.*` are gitignored
