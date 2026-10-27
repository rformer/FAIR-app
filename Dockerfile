# syntax=docker/dockerfile:1
# Hardened images for the platform services (F-001 T-00c, constitution S2/S5).
# One build stage; one final stage per binary, each holding only that binary:
#   docker build .                          iam (the default, last stage)
#   docker build --target posture .         posture service (F-015)
#   docker build --target posture-scanner . deployment drift scanner (F-015 T-27)
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
# Pinned OSCAL schema and manifest embedded by internal/oscal (posture).
COPY third_party/oscal/oscal.go third_party/oscal/MANIFEST.json ./third_party/oscal/
COPY third_party/oscal/schemas/oscal_complete_schema.json ./third_party/oscal/schemas/
ARG VERSION=dev
RUN for c in iam posture posture-scanner; do       go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/$c ./cmd/$c || exit 1;     done

FROM gcr.io/distroless/static-debian12:nonroot AS posture-scanner
COPY --from=build /out/posture-scanner /posture-scanner
USER 65532:65532
ENTRYPOINT ["/posture-scanner"]

FROM gcr.io/distroless/static-debian12:nonroot AS posture
COPY --from=build /out/posture /posture
USER 65532:65532
EXPOSE 8443 9443
ENTRYPOINT ["/posture"]

FROM gcr.io/distroless/static-debian12:nonroot AS iam
COPY --from=build /out/iam /iam
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/iam"]
