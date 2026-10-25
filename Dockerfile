# syntax=docker/dockerfile:1.7
# iam service image (F-001 T-00c; constitution S2, S5; ADR-003).
#
# - Static Go binary built against the frozen Go Cryptographic Module
#   (GOFIPS140=v1.0.0), which also makes fips140=on the runtime default.
# - Distroless static base: no shell, no package manager, non-root UID 65532.
# - Run with a read-only root filesystem (see deploy/k8s/iam.yaml).
#
# Pin the base images by digest in release builds (Dependabot keeps them current).

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH GOFIPS140=v1.0.0 \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/iam ./cmd/iam

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="fair-iam" \
      org.opencontainers.image.description="FAIR Risk Platform identity, BU hierarchy and RBAC service" \
      org.opencontainers.image.source="https://github.com/rformer/fair-app"
COPY --from=build /out/iam /iam
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/iam"]
CMD ["serve"]
