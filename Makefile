# AI Continuity Platform — Core
# Makefile for local development. CI runs the same targets via vault-gate.yml.
#
# See 00_CI_Security_Policy.md for the authoritative definition of every check.
# This Makefile mirrors the CI so that a passing local run predicts a passing CI.

SHELL := /bin/bash
GO    ?= go
PKG   := ./...

# --- metadata -----------------------------------------------------------------

BINARIES := sagvd acp-compute acpctl acp-bootstrap acp-demo
VERSION  ?= 0.0.0-dev
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# Reproducible-build flags. Two builds from the same source on the same
# Go version produce byte-identical output. SLSA L3-style guarantee.
#
#   -X main.version / main.commit   stamp version metadata into the binary
#   -buildid=                       remove the random build ID Go links by default
#   -s -w                           strip symbol table + DWARF
# `-trimpath` (a `go build` flag, not an ldflag) removes absolute paths
# from the binary so the build is location-independent.
#
# DEBUG=1 keeps the symbol table and DWARF (no -s -w) for a debugger or a
# profiler; everything else, -trimpath included, stays the same, so the
# debug build is as reproducible as the stripped one, only larger.
# Release binaries are always the stripped build.
DEBUG ?= 0
ifeq ($(DEBUG),1)
LDFLAGS       := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -buildid=
else
LDFLAGS       := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -buildid= -s -w
endif
GOFLAGS_REPRO := -trimpath -ldflags '$(LDFLAGS)'

.PHONY: all
all: fmt vet build test

# --- build --------------------------------------------------------------------

.PHONY: build
build: $(BINARIES:%=bin/%)

# CGO_ENABLED=0: static binaries that run on any linux/amd64 without a
# libc to match, and that anyone rebuilds byte for byte from any host with
# the pinned Go (docs/operator/05_release_procedure.md §5). Nothing in the
# tree imports "C"; the TEE drivers are reached through ioctls.
bin/%: cmd/%
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(GOFLAGS_REPRO) -o $@ ./$<

# verify-reproducible builds every binary twice with identical flags and
# diffs the resulting bytes. Failure means a non-determinism source
# crept in (random build IDs, embedded timestamps, GOPATH leakage,
# CGO non-determinism). CI runs this as sub-check 18 in vault-gate.yml.
.PHONY: verify-reproducible
verify-reproducible:
	@$(MAKE) --no-print-directory clean-bin
	@$(MAKE) --no-print-directory build
	@mkdir -p dist/repro
	@for b in $(BINARIES); do cp bin/$$b dist/repro/$$b.first; done
	@$(MAKE) --no-print-directory clean-bin
	@$(MAKE) --no-print-directory build
	@for b in $(BINARIES); do \
	  if cmp -s dist/repro/$$b.first bin/$$b; then \
	    echo "  $$b: byte-identical across two builds"; \
	  else \
	    echo "  $$b: BUILDS DIFFER — non-determinism source present"; \
	    sha256sum dist/repro/$$b.first bin/$$b; \
	    exit 1; \
	  fi; \
	done
	@rm -rf dist/repro
	@echo "reproducible-build check: PASS"

.PHONY: clean-bin
clean-bin:
	@rm -rf bin

# --- format / vet / lint ------------------------------------------------------

.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

.PHONY: fmt-check
fmt-check:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || { echo "gofmt: files are not formatted"; exit 1; }

.PHONY: vet
vet:
	$(GO) vet $(PKG)

.PHONY: lint
lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run $(PKG)

# --- tests --------------------------------------------------------------------

.PHONY: test
test:
	$(GO) test -count=1 $(PKG)

.PHONY: test-race
test-race:
	$(GO) test -count=1 -race $(PKG)

.PHONY: test-integration
test-integration:
	$(GO) test -count=1 -tags=integration ./test/integration/...

.PHONY: test-doctrine
test-doctrine:
	$(GO) test -count=1 ./test/doctrine/...

# coverage writes a cross-package profile: a statement counts as covered
# when any test in the module executes it (policy: ci-security-policy.md §8).
.PHONY: coverage
coverage:
	$(GO) test -count=1 -coverpkg=./... -coverprofile=coverage.out $(PKG)

# --- benchmarks ---------------------------------------------------------------

# bench runs every Go benchmark across the module and writes results
# to dist/bench.out. The CI workflow .github/workflows/bench.yml uses
# this file as the "current PR" side of the benchstat comparison;
# the "main branch" baseline is restored from a cached upstream run.
.PHONY: bench
bench:
	@mkdir -p dist
	$(GO) test -bench=. -benchmem -run=^$$ -count=5 -benchtime=1s $(PKG) | tee dist/bench.out

# bench-quick runs benchmarks at lower count for local iteration.
.PHONY: bench-quick
bench-quick:
	$(GO) test -bench=. -benchmem -run=^$$ -count=1 -benchtime=300ms $(PKG)

# bench-compare runs benchstat against two bench output files. Usage:
#   make bench-compare BASE=baseline.out HEAD=current.out
.PHONY: bench-compare
bench-compare:
	@command -v benchstat >/dev/null || { echo "benchstat not installed: go install golang.org/x/perf/cmd/benchstat@latest"; exit 1; }
	@test -f "$(BASE)" || { echo "BASE=$(BASE) does not exist"; exit 1; }
	@test -f "$(HEAD)" || { echo "HEAD=$(HEAD) does not exist"; exit 1; }
	benchstat $(BASE) $(HEAD)

# --- mutation testing ---------------------------------------------------------

# Mutation testing exercises our test suite by automatically introducing
# small bugs (mutations) into source code and checking whether tests
# catch them. A mutation that survives means tests are weak in that
# region — the fix is to add a test, not to suppress the mutation.
#
# Tool: github.com/avito-tech/go-mutesting (fork of zimmski's). Install:
#   go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest
#
# The Make targets below scope mutation testing to security-critical
# packages because full-tree mutation is multi-hour. Run nightly via
# .github/workflows/mutation.yml; manual on-demand via these targets.

# Packages we mutation-test. Order matters only insofar as failures
# in earlier packs are surfaced first.
MUTATION_PACKAGES := \
	./internal/shared/crypto/... \
	./internal/audit/chain/... \
	./internal/vault/keys/... \
	./internal/recvvalidator/... \
	./internal/shared/tee/...

.PHONY: mutation
mutation:
	@command -v go-mutesting >/dev/null || { \
	  echo "go-mutesting not installed: go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest"; \
	  exit 1; \
	}
	@mkdir -p dist
	@for pkg in $(MUTATION_PACKAGES); do \
	  echo "==> mutating $$pkg"; \
	  go-mutesting $$pkg --debug=false --do-not-remove-tmp-folder=false 2>&1 | tee -a dist/mutation.out; \
	  echo; \
	done

# mutation-quick: run on a single package for fast iteration.
# Usage: make mutation-quick PKG=./internal/audit/chain/...
.PHONY: mutation-quick
mutation-quick:
	@command -v go-mutesting >/dev/null || { \
	  echo "go-mutesting not installed: go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest"; \
	  exit 1; \
	}
	@test -n "$(PKG)" || { echo "PKG argument required, e.g. PKG=./internal/audit/chain/..."; exit 1; }
	go-mutesting $(PKG)

# --- security -----------------------------------------------------------------

.PHONY: vuln
vuln:
	@command -v govulncheck >/dev/null || { echo "govulncheck not installed"; exit 1; }
	govulncheck $(PKG)
	cd scripts/hardware-test/aws-nitro/vsock-attest && GOOS=linux GOARCH=amd64 govulncheck ./...

.PHONY: secrets
secrets:
	@command -v gitleaks >/dev/null || { echo "gitleaks not installed"; exit 1; }
	gitleaks detect --no-git -v

.PHONY: sbom
sbom:
	@command -v syft >/dev/null || { echo "syft not installed"; exit 1; }
	@mkdir -p dist
	syft dir:. -o spdx-json=dist/sbom.spdx.json

# --- doctrine / policy --------------------------------------------------------

.PHONY: terminology
terminology:
	bash scripts/terminology_check.sh

.PHONY: cli-reference
cli-reference:
	bash scripts/gen_cli_reference.sh

.PHONY: license-headers
license-headers:
	bash scripts/license_header_check.sh

.PHONY: coverage-thresholds
coverage-thresholds: coverage
	bash scripts/coverage_check.sh

.PHONY: dep-allowlist
dep-allowlist:
	bash scripts/check_dep_allowlist.sh

.PHONY: dep-depth
dep-depth:
	bash scripts/check_dep_depth.sh

# --- demo ---------------------------------------------------------------------

# Narrated end-to-end walkthrough of the vertical slice. Useful for onboarding
# a new operator or for a live pilot demo. The demo runs the existing
# integration test as a guided flow and prints one-line commentary per stage.
.PHONY: demo
demo:
	bash scripts/demo.sh

# regen-demo runs the self-contained cross-hardware regeneration flagship
# (cmd/acp-demo): no compose, no config, no TEE hardware. This is the
# "one command" showcase — also the default entrypoint of the root Dockerfile
# (docker run --rm vaultgenome).
.PHONY: regen-demo
regen-demo:
	$(GO) run ./cmd/acp-demo

# ---- Phase-1 Docker Compose demo --------------------------------------------
#
# Five targets that turn a fresh clone into a running sagvd + acp-compute pair
# and back again. Authoritative layout + design notes live in
# ../deploy/compose/README.md; this section only wires the Makefile surface.
#
# Pathing: the Makefile sits at /core, the deploy tree at /deploy/compose.
# All targets set their working directory to DEMO_DIR so a `make demo-up`
# from anywhere under /core does the right thing.

DEMO_DIR            := $(CURDIR)/deploy/compose
DEMO_COMPOSE        := $(DEMO_DIR)/docker-compose.yml
DEMO_SECRETS_DIR    := $(DEMO_DIR)/secrets
DEMO_COMPOSE_CMD    ?= docker compose
DEMO_SAGVD_URL      ?= http://127.0.0.1:9080
DEMO_SAGVD_HEALTH   ?= http://127.0.0.1:9091
DEMO_WORKER_HEALTH  ?= http://127.0.0.1:9092
DEMO_READY_TIMEOUT  ?= 30

.PHONY: demo-certs
demo-certs:
	@echo "==> generating demo secrets under $(DEMO_SECRETS_DIR)"
	@cd $(DEMO_DIR)/keygen && $(GO) run . -out $(DEMO_SECRETS_DIR)

.PHONY: demo-certs-force
demo-certs-force:
	@echo "==> regenerating demo secrets (force) under $(DEMO_SECRETS_DIR)"
	@cd $(DEMO_DIR)/keygen && $(GO) run . -out $(DEMO_SECRETS_DIR) -force

# demo-genome fine-tunes a tiny model with the real vg_genome worker and
# seals its genome into deploy/compose/genomes (with the base model under
# deploy/compose/models): what `make demo-submit` asks the worker to
# restore. Needs the worker runtime on the host (workers/genome/README.md).
.PHONY: demo-genome
demo-genome: bin/acpctl
	@ACPCTL=$(CURDIR)/bin/acpctl bash $(DEMO_DIR)/scripts/make_genome.sh

# demo-up needs somewhere for sagvd to keep its Return Path audit log.
$(DEMO_DIR)/audit:
	@mkdir -p $@

.PHONY: demo-up
demo-up: demo-certs $(DEMO_DIR)/audit
	@echo "==> building + starting compose stack"
	@cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) up -d --build
	@echo "==> waiting for sagvd /readyz (up to $(DEMO_READY_TIMEOUT)s)"
	@end=$$(( $$(date +%s) + $(DEMO_READY_TIMEOUT) )); \
	while : ; do \
	    if curl -fsS $(DEMO_SAGVD_HEALTH)/readyz >/dev/null 2>&1 ; then \
	        echo "==> sagvd ready at $(DEMO_SAGVD_HEALTH)"; break; \
	    fi; \
	    if [ $$(date +%s) -ge $$end ]; then \
	        echo "demo-up: sagvd did not become ready within $(DEMO_READY_TIMEOUT)s" >&2; \
	        cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) logs sagvd >&2; \
	        exit 1; \
	    fi; \
	    sleep 1; \
	done
	@echo "==> stack up. Try 'make demo-submit'."

.PHONY: demo-down
demo-down:
	@echo "==> stopping compose stack"
	@cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) down --remove-orphans

.PHONY: demo-submit
demo-submit:
	@SAGVD_URL=$(DEMO_SAGVD_URL) bash $(DEMO_DIR)/scripts/submit_job.sh

# demo-test is the automated version of demo-submit + health probe.
# It's what CI could run once a Docker-enabled runner is available;
# manual operators normally reach for `demo-submit` instead.
.PHONY: demo-test
demo-test:
	@echo "==> probing sagvd /readyz"
	@curl -fsS $(DEMO_SAGVD_HEALTH)/readyz >/dev/null || { echo "sagvd not ready" >&2; exit 1; }
	@echo "==> probing acp-compute /healthz"
	@curl -fsS $(DEMO_WORKER_HEALTH)/healthz >/dev/null || { echo "acp-compute not alive" >&2; exit 1; }
	@echo "==> submitting a job (should succeed)"
	@SAGVD_URL=$(DEMO_SAGVD_URL) bash $(DEMO_DIR)/scripts/submit_job.sh >/dev/null
	@echo "==> demo-test: PASS"

.PHONY: demo-logs
demo-logs:
	@cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) logs --tail=200 -f

# --- aggregate gates ----------------------------------------------------------

.PHONY: vault-gate
vault-gate: fmt-check vet build test test-race test-doctrine lint terminology license-headers vuln secrets coverage-thresholds dep-allowlist dep-depth
	@echo "vault-gate: PASS"

# --- housekeeping -------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf bin dist coverage.out coverage.html
