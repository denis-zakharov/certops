.PHONY: all build release run test fmt fmt-check lint check audit clean install help

all: fmt-check lint test build ## Run every check, then build

build: ## Debug build
	cargo build

release: ## Optimized build
	cargo build --release

run: ## Run the CLI, e.g. make run ARGS="text keystore.p12"
	cargo run -- $(ARGS)

test: ## Run unit tests
	cargo test

fmt: ## Format the code
	cargo fmt

fmt-check: ## Verify formatting
	cargo fmt --check

lint: ## Clippy, warnings are errors
	cargo clippy --all-targets -- -D warnings

check: ## Fast type check
	cargo check --all-targets

audit: ## Scan dependencies for advisories (needs cargo-audit)
	cargo audit

install: ## Install the binary into ~/.cargo/bin
	cargo install --path .

clean: ## Remove build artifacts
	cargo clean

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
