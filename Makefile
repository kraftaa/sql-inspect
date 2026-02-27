.PHONY: fmt check test lint ci smoke-openai smoke-bedrock audit

fmt:
	cargo fmt --all

check:
	cargo check

test:
	cargo test

lint:
	cargo clippy --all-targets --all-features -- -D warnings

smoke-openai:
	./scripts/smoke-test.sh openai

smoke-bedrock:
	./scripts/smoke-test.sh bedrock

audit:
	cargo deny check advisories licenses bans sources

ci:
	cargo fmt --all --check
	cargo test
	cargo clippy --all-targets --all-features -- -D warnings
