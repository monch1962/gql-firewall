GO_BIN := /usr/local/go/bin/go
GOLANGCI_BIN := $(HOME)/go/bin/golangci-lint
NILAWAY_BIN := $(HOME)/go/bin/nilaway
OPA_BIN := $(HOME)/.local/bin/opa
BINARY := gql-firewall
LD_FLAGS := -ldflags="-s -w"

.PHONY: all build test lint vet nilaway docker clean help

all: lint vet build test

build:
	$(GO_BIN) build $(LD_FLAGS) -trimpath -o $(BINARY) ./cmd/server/

test:
	$(GO_BIN) test ./... -count=1
	$(OPA_BIN) test opa-policies/

lint:
	PATH="/usr/local/go/bin:$(PATH)" $(GOLANGCI_BIN) run --timeout 2m

vet:
	$(GO_BIN) vet ./...

nilaway:
	$(NILAWAY_BIN) -include-pkgs="github.com/monch1962/gql-firewall/internal/opa,github.com/monch1962/gql-firewall/internal/proxy,github.com/monch1962/gql-firewall/cmd/server,github.com/monch1962/gql-firewall/internal/parser,github.com/monch1962/gql-firewall/internal/metrics" ./... 2>&1 | grep -v "_test.go" | grep -q "error:" && echo "FAILED" || echo "nilaway: PASS"

docker:
	docker build -t $(BINARY):latest .

clean:
	rm -f $(BINARY)
	$(GO_BIN) clean ./...

help:
	@echo "Targets:"
	@echo "  build   - build Go binary"
	@echo "  test    - run all Go and Rego tests"
	@echo "  lint    - run golangci-lint"
	@echo "  vet     - run go vet"
	@echo "  nilaway - run nilaway (production code only)"
	@echo "  docker  - build Docker image"
	@echo "  clean   - remove binary and build cache"
	@echo "  all     - lint, vet, build, test"
