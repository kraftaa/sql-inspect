# sql-ai-explainer

CLI tool that reviews SQL for reliability and cost risk.

It combines:

- deterministic static checks for common anti-patterns
- LLM-generated structured explanations and suggestions

Current structured output includes:

- `summary`
- `tables`
- `joins`
- `filters`
- `risks`
- `suggestions`
- `anti_patterns`
- `findings` with `rule_id`, `severity`, `message`, `why_it_matters`, `evidence`
- `estimated_cost_impact`
- `confidence`

Supports:

- OpenAI (`/v1/responses`)
- AWS Bedrock (`invoke_model`)
- dialect-aware static analysis (`generic`, `athena`)

Static checks currently detect patterns such as:

- `SELECT *`
- missing `WHERE`
- multiple joins / wide joins
- leading wildcard `LIKE '%x'`
- `CROSS JOIN`

The tool may also suggest adding `LIMIT` for likely ad hoc exploration queries, but missing `LIMIT` is not treated as a general anti-pattern.

Athena mode adds heuristics such as:

- no obvious partition/date filter
- `ORDER BY` without `LIMIT`
- `COUNT(DISTINCT ...)` suggestion toward `approx_distinct`

## Project Layout

```text
sql-ai-explainer/
  Cargo.toml
  src/
    main.rs
    lib.rs
    error.rs
    prompt.rs
    providers/
      mod.rs
      openai.rs
      bedrock.rs
```

## Prerequisites

- Rust (stable)
- For OpenAI usage:
  - `OPENAI_API_KEY`
  - optional: `OPENAI_MODEL` (default is `gpt-4.1-mini`)
- For Bedrock usage:
  - AWS credentials (profile/role/env)
  - `AWS_REGION`
  - `BEDROCK_MODEL_ID` (example: `anthropic.claude-3-5-sonnet-20241022-v2:0`)

## Build

```bash
cargo check
```

## Local Commands

```bash
make fmt
make check
make test
make lint
make ci
```

Additional commands:

```bash
make smoke-openai
make smoke-bedrock
make audit
make secrets
```

## Usage

Provide exactly one of:

- `--sql "<query>"`
- `--file <path>`
- `--dir <path>`

Optional:

- `--provider openai|bedrock` (default: `openai`)
- `--dialect generic|athena`
- `--glob <pattern>` for directory scans (default: `*.sql`)
- `--config <path>` to load `sql-inspect.toml`
- `--static-only` to skip the LLM and run deterministic checks only
- `--fail-on low|medium|high` to exit non-zero when findings meet the threshold
- `--json` to print raw JSON returned by the model

### OpenAI Example

```bash
export OPENAI_API_KEY="..."
export OPENAI_MODEL="gpt-4.1-mini"

cargo run -- --provider openai --file examples/query.sql
```

### Bedrock Example

```bash
export AWS_REGION="us-east-1"
export BEDROCK_MODEL_ID="anthropic.claude-3-5-sonnet-20241022-v2:0"

cargo run -- --provider bedrock --file examples/query.sql
```

### Inline SQL Example

```bash
cargo run -- --provider openai --sql "select * from orders o join customers c on o.customer_id = c.id where o.created_at >= current_date - interval '30 days'"
```

### Directory Scan Example

Directory scanning currently runs in static-analysis mode so you can use it in CI without provider credentials.

```bash
cargo run -- --dir models --dialect athena --glob "*.sql" --fail-on high
```

### Static-Only Example

```bash
cargo run -- --file examples/query.sql --static-only
```

Tested result with the included sample query:

- summary: static analysis for `examples/query.sql`
- estimated cost impact: `low`
- no findings for the current sample query

### Config File Example

Create `sql-inspect.toml` in the project root:

```toml
dialect = "athena"
fail_on = "high"
glob = "*.sql"
suggest_limit_for_exploratory = true
static_only = false
```

An example is included at `sql-inspect.toml.example`.

## Tested Commands

These commands were run successfully against the current repository:

```bash
cargo run -- --file examples/query.sql --static-only
cargo run -- --dir examples --dialect athena --glob "*.sql" --fail-on high
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Smoke Test Script

For a real provider smoke test with your credentials:

```bash
./scripts/smoke-test.sh openai
./scripts/smoke-test.sh bedrock
```

You can also pass a different SQL file:

```bash
./scripts/smoke-test.sh openai path/to/query.sql
```

## Output Modes

Default mode validates model output against the `SqlExplanation` struct, merges local static findings, and prints a readable summary.

`--json` mode prints the raw model output, useful when troubleshooting schema mismatches.

## Troubleshooting

- `missing required environment variable`: set the reported env var.
- `Model did not return valid JSON`: run with `--json` and inspect the raw response.
- `Unexpected ... response shape`: provider returned a different schema; adjust the extractor in:
  - `src/providers/openai.rs`
  - `src/providers/bedrock.rs`

## Secret Safety

Local secret files are ignored by git:

- `.env`
- `.env.*`

Template files are still allowed:

- `.env.example`
- `.env.sample`
- `.env.template`

For local scanning, if `gitleaks` is installed:

```bash
make secrets
```

## CI And Release

GitHub Actions included in this repo:

- `CI`: runs format, tests, and clippy on pushes/PRs
- `Audit`: runs `cargo-deny` on pushes/PRs and weekly on Mondays
- `Secrets`: runs `gitleaks` on pushes/PRs
- `Release`: builds release binaries for Linux and macOS on `v*` tags and attaches them to a GitHub release
