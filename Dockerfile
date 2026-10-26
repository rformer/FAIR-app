# syntax=docker/dockerfile:1
# Hardened image for the iam service (F-001 T-00c, constitution S2/S5).
# - FIPS 140-3: built with GOFIPS140=v1.0.0; go.mod sets fips140=on at runtime.
# - Static, CGO-free binary on distroless: no shell, no package manager.
# - Runs as non-root (65532) and works with a read-only root filesystem.
# TODO(F-012): pin both base images by digest; Dependabot keeps digests current.

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY db/embed.go ./db/
COPY db/migrations ./db/migrations
COPY internal ./internal
COPY pkg ./pkg
# Profile packages embedded in iam migrate (F-015 T-10).
COPY profiles/embed.go ./profiles/
COPY profiles/packages ./profiles/packages
ARG VERSION=dev
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/iam ./cmd/iam

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/iam /iam
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/iam"]
