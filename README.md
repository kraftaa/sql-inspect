# sql-ai-explainer

CLI tool that sends SQL to an LLM and expects strict JSON back:

- `summary`
- `tables`
- `joins`
- `filters`
- `risks`
- `suggestions`

Supports:

- OpenAI (`/v1/responses`)
- AWS Bedrock (`invoke_model`)

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
```

## Usage

Provide exactly one of:

- `--sql "<query>"`
- `--file <path>`

Optional:

- `--provider openai|bedrock` (default: `openai`)
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

Default mode validates model output against the `SqlExplanation` struct and prints a readable summary.

`--json` mode prints the raw model output, useful when troubleshooting schema mismatches.

## Troubleshooting

- `missing required environment variable`: set the reported env var.
- `Model did not return valid JSON`: run with `--json` and inspect the raw response.
- `Unexpected ... response shape`: provider returned a different schema; adjust the extractor in:
  - `src/providers/openai.rs`
  - `src/providers/bedrock.rs`

## CI And Release

GitHub Actions included in this repo:

- `CI`: runs format, tests, and clippy on pushes/PRs
- `Audit`: runs `cargo-deny` on pushes/PRs and weekly on Mondays
- `Release`: builds release binaries for Linux and macOS on `v*` tags and attaches them to a GitHub release
