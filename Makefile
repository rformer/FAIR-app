export GOFIPS140 ?= v1.0.0
export CGO_ENABLED ?= 0

.PHONY: build test test-db migrate lint fmt vet image clean

build:
	go build -trimpath -o bin/iam ./cmd/iam

test:
	CGO_ENABLED=1 go test -race -count=1 ./...

# Requires PostgreSQL 16+ and psql. Provide an admin connection via libpq vars, e.g.
#   make test-db PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=...
test-db:
	FAIR_TEST_PG=1 go test -count=1 -v ./db/tests/

# Applies the embedded migrations and release catalog as app_migrator (T-02b).
# Needs PGDATABASE, FAIR_MIGRATOR_PASSWORD_FILE and libpq connection vars;
# FAIR_ENV=development locally (production requires PGSSLMODE=verify-full).
migrate: build
	./bin/iam migrate

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run

image:
	docker build -t fair-iam:dev .

clean:
	rm -rf bin coverage.out
