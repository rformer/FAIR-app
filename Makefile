VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS  ?= -mod=readonly
export GOFLAGS

.PHONY: all build test test-fips test-integration lint image run kind-load clean

all: lint test build

## build: FIPS-mode static binary (Go Cryptographic Module v1.0.0)
build:
	CGO_ENABLED=0 GOFIPS140=v1.0.0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/iam ./cmd/iam

test:
	go test -race -count=1 ./...

## test-fips: unit tests in FIPS mode, failing if FIPS mode is off
test-fips:
	GODEBUG=fips140=on FAIR_REQUIRE_FIPS=1 go test -count=1 ./...

## test-integration: needs FAIR_TEST_PG_ADMIN_URL (PostgreSQL 16+) and FAIR_TEST_NATS_URL (JetStream)
test-integration:
	go test -tags integration -count=1 -v ./test/integration/...

lint:
	test -z "$$(gofmt -l .)"
	go vet -tags integration ./...
	golangci-lint run --build-tags integration

image:
	docker build --build-arg VERSION=$(VERSION) -t fair-iam:dev .

## run: local dev server (FIPS mode on; audit to stdout)
run: build
	GODEBUG=fips140=on ./bin/iam serve

## kind-load: build the image and deploy to the current kind cluster
kind-load: image
	kind load docker-image fair-iam:dev
	kubectl apply -f deploy/k8s/namespace.yaml -f deploy/k8s/iam.yaml
	kubectl -n fair rollout status deploy/iam --timeout=120s

clean:
	rm -rf bin dist
