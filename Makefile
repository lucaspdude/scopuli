# scopuli — Makefile

BINARY        := scopuli
BIN_DIR       := bin
IMAGE         := scopuli:dev
CONTAINER     := scopuli-smoke
DATA_DIR      := /tmp/scopuli-smoke
SMOKE_PASS    := smoketest-passphrase-9f3a2b

GO            := go
GOFLAGS       := -trimpath -buildvcs=true
LDFLAGS       := -s -w

.PHONY: build
build: $(BIN_DIR)/$(BINARY)

$(BIN_DIR)/$(BINARY):
	$(GO) build -tags sqlite_fts5 $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $@ ./cmd/scopuli

.PHONY: test
test:
	$(GO) test -tags sqlite_fts5 -race -count=1 ./...

.PHONY: test-coverage
test-coverage:
	$(GO) test -tags sqlite_fts5 -race -coverprofile=coverage.out -count=1 ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: lint
lint:
	$(GO) vet ./...
	gofmt -l . | tee /tmp/gofmt-issues; test ! -s /tmp/gofmt-issues

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE) .

.PHONY: docker-run
docker-run:
	mkdir -p $(DATA_DIR)
	# scopuli runs as UID 65532 (distroless nonroot). Make the bind-mount
	# host directory writable by that user.
	chown -R 65532:65532 $(DATA_DIR) 2>/dev/null || chmod -R a+rwX $(DATA_DIR)
	docker rm -f $(CONTAINER) 2>/dev/null || true
	docker run --rm --name $(CONTAINER) -d \
	  -e MASTER_PASSWORD=$(SMOKE_PASS) \
	  -v $(DATA_DIR):/data \
	  -p 127.0.0.1:8080:8080 \
	  $(IMAGE)

.PHONY: docker-stop
docker-stop:
	docker rm -f $(CONTAINER) 2>/dev/null || true

.PHONY: smoke
smoke: build
	./scripts/smoke-test.sh

.PHONY: smoke-docker
smoke-docker: docker-build docker-run
	./scripts/smoke-test.sh docker

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out
	docker rm -f $(CONTAINER) 2>/dev/null || true
	rm -rf $(DATA_DIR)

.PHONY: deps
deps:
	$(GO) mod tidy
	$(GO) mod verify
