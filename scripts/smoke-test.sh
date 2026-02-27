#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <openai|bedrock> [sql-file]" >&2
  exit 2
fi

provider="$1"
sql_file="${2:-examples/query.sql}"

if [[ ! -f "$sql_file" ]]; then
  echo "SQL file not found: $sql_file" >&2
  exit 2
fi

case "$provider" in
  openai)
    : "${OPENAI_API_KEY:?OPENAI_API_KEY must be set}"
    export OPENAI_MODEL="${OPENAI_MODEL:-gpt-4.1-mini}"
    ;;
  bedrock)
    : "${AWS_REGION:?AWS_REGION must be set}"
    : "${BEDROCK_MODEL_ID:?BEDROCK_MODEL_ID must be set}"
    ;;
  *)
    echo "Unsupported provider: $provider" >&2
    echo "Expected one of: openai, bedrock" >&2
    exit 2
    ;;
esac

echo "Running smoke test with provider=$provider file=$sql_file"
cargo run -- --provider "$provider" --file "$sql_file"
