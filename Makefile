# Top-level Makefile for the user-content platform.
#
# Targets follow the GoBeaver convention described in
# package-structure.md. New modules added to this repo should
# extend MODULES and pick up every target for free.
#
# Single-module variant — when the repo is split into multiple
# go.mod sub-modules, replace MODULES with a per-module list
# (see filekit/Makefile for the worked example) and fan every
# target out with the `for d in $(MODULES); do (cd $$d && ...);`
# pattern.

GO        ?= go
GOSEC_VERSION     ?= v2.29.0
GOVULNCHECK_VERSION ?= latest

.PHONY: test test-race test-coverage lint fmt fmt-check vet tidy tidy-check \
        check ci gosec vuln sec fuzz fuzz-long browsertest golden deps-core \
        build run-pageservice run-playground examples clean

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run

fmt:
	$(GO) fmt ./...

# fmt-check is what CI runs: it reports rather than rewrites.
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi

tidy-check:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

build:
	$(GO) build ./...

run-pageservice:
	$(GO) run ./cmd/pageservice

run-playground:
	$(GO) run ./cmd/playground

# examples runs every example and checks its output still matches
# what the docs claim. Examples rot silently otherwise.
examples:
	$(GO) test ./examples/ -count=1 -v

# Fuzz both sanitizers. FUZZTIME overrides the per-target budget.
FUZZTIME ?= 60s
fuzz:
	$(GO) test ./usercontent/ -run '^$$' -fuzz FuzzSanitizeHTML -fuzztime=$(FUZZTIME)
	$(GO) test ./usercontent/ -run '^$$' -fuzz FuzzSanitizeCSS -fuzztime=$(FUZZTIME)

# browsertest loads sanitized corpus pages in real engines. The Go
# output check re-parses with the same parser that produced the
# output; only a browser settles what a browser does.
browsertest:
	$(GO) run ./cmd/corpusexport -out browsertest/pages
	cd browsertest && npm install --no-package-lock && npx playwright install --with-deps
	cd browsertest && node check.mjs pages

# golden rewrites the pinned per-profile output fixtures. Bump the
# profile's Version first: stored pages are re-sanitized when it moves.
golden:
	$(GO) test ./usercontent/ -run TestGolden -update

# deps-core asserts the security core's dependency surface.
deps-core:
	@deps="$$($(GO) list -deps ./usercontent | grep -v '^github.com/gobeaver/go-beaver-tag-sanitization' | grep '\.' | grep -v '^golang.org/x/net/html' || true)"; \
	if [ -n "$$deps" ]; then \
		echo "usercontent must depend only on golang.org/x/net/html; found:"; echo "$$deps"; exit 1; \
	fi; \
	echo "usercontent dependency surface OK"

# fuzz-long is the depth run; FUZZTIME defaults to an hour a target.
fuzz-long:
	$(MAKE) fuzz FUZZTIME=60m

gosec:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

sec: gosec vuln

# `make check` is the developer-day gate.
check: fmt-check vet deps-core test lint

# `make ci` is what CI runs — also pulls the security tools.
ci: deps fmt-check tidy-check vet deps-core test-race lint gosec vuln

deps:
	$(GO) mod download

clean:
	rm -f coverage.out
