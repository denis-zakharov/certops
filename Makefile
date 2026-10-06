.PHONY: all build release run test fmt fmt-check lint check audit clean install test-p12 help

TEST_P12_PASSWORD ?= changeit

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

test-p12: ## Generate test.p12 (password: changeit) for manual testing; needs openssl
	@d=$$(mktemp -d) && trap 'rm -rf $$d' EXIT && cd $$d && \
	openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
		-subj "/CN=Test Root CA/O=certops" -days 365 2>/dev/null && \
	openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
		-subj "/CN=test.example.com/O=certops" 2>/dev/null && \
	printf "subjectAltName=DNS:test.example.com,DNS:*.example.com,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n" > ext && \
	openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out leaf.crt \
		-days 365 -extfile ext 2>/dev/null && \
	openssl pkcs12 -export -inkey leaf.key -in leaf.crt -certfile ca.crt \
		-out "$(CURDIR)/test.p12" -passout pass:$(TEST_P12_PASSWORD) && \
	echo "wrote test.p12 (password: $(TEST_P12_PASSWORD))"

clean: ## Remove build artifacts
	cargo clean

help: ## List targets
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
