# syntax=docker/dockerfile:1
# Hardened images for the platform services (F-001 T-00c, constitution S2/S5).
# One build stage; one final stage per binary, each holding only that binary:
#   docker build .                          iam (the default, last stage)
#   docker build --target posture .         posture service (F-015)
#   docker build --target posture-scanner . deployment drift scanner (F-015 T-27)
#   docker build --target fips-probe .      node FIPS probe (F-015 T-29)
#   docker build --target audit .           audit trail service (F-002 T-05), with /fair-audit-verify (T-10)
#   docker build --target risk .            risk data service (F-003 T-04)
#   docker build --target engine .          simulation engine, Python (F-005 T-04, ADR-013)
# - FIPS 140-3: built with GOFIPS140=v1.0.0; go.mod sets fips140=on at runtime.
# - Static, CGO-free binary on distroless: no shell, no package manager.
# - Runs as non-root (65532) and works with a read-only root filesystem.
# TODO(F-012): pin both base images by digest; Dependabot keeps digests current.

ARG GO_VERSION=1.26
ARG PYTHON_IMAGE=python:3.12.16-slim-bookworm

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
RUN for c in iam posture posture-scanner fips-probe gateway audit risk; do \
      go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/$c ./cmd/$c || exit 1; \
    done && \
    go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/fair-audit-verify ./cmd/audit-verify

FROM gcr.io/distroless/static-debian12:nonroot AS fips-probe
COPY --from=build /out/fips-probe /fips-probe
USER 65532:65532
ENTRYPOINT ["/fips-probe"]

FROM gcr.io/distroless/static-debian12:nonroot AS posture-scanner
COPY --from=build /out/posture-scanner /posture-scanner
USER 65532:65532
ENTRYPOINT ["/posture-scanner"]

FROM gcr.io/distroless/static-debian12:nonroot AS posture
COPY --from=build /out/posture /posture
USER 65532:65532
EXPOSE 8443 9443
ENTRYPOINT ["/posture"]

FROM gcr.io/distroless/static-debian12:nonroot AS audit
COPY --from=build /out/audit /audit
# The offline verifier (F-002 T-10), so air-gapped bundles carry it:
#   docker run --rm --entrypoint /fair-audit-verify -v "$PWD:/e:ro" <image> verify-export /e/bundle.zip
COPY --from=build /out/fair-audit-verify /fair-audit-verify
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/audit"]

FROM gcr.io/distroless/static-debian12:nonroot AS risk
COPY --from=build /out/risk /risk
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/risk"]

FROM gcr.io/distroless/static-debian12:nonroot AS gateway
COPY --from=build /out/gateway /gateway
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/gateway"]

# The simulation engine (F-005 T-04, ADR-013): Python 3.12 with the locked
# dependencies (hashes required) on distroless static, with exactly the
# Debian libraries Python and the wheels link against, copied with their
# dpkg records so the SBOM and the vulnerability scan see them. No shell, no
# package manager, and no OpenSSL: the engine does no cryptography
# (engine-gate terminates TLS), so Python's _ssl and _hashlib are removed.
# NumPy's CPU dispatch is pinned by fairsim.cpu at import.
FROM ${PYTHON_IMAGE} AS engine-build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY engine/requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes --no-deps --target /opt/site -r /tmp/requirements.lock \
 && py=/usr/local/lib/python3.12 \
 && rm -rf "$py/ensurepip" "$py/idlelib" "$py/tkinter" "$py/test" "$py/site-packages/"pip* \
           "$py/lib-dynload/"_ssl.* "$py/lib-dynload/"_hashlib.* "$py/lib-dynload/"_tkinter.* "$py/lib-dynload/"_curses*.* \
           "$py/lib-dynload/"_gdbm.* "$py/lib-dynload/"_dbm.* "$py/lib-dynload/"_sqlite3.* "$py/lib-dynload/"nis.* "$py/lib-dynload/"readline.* \
 && find /opt/site "$py" -name '__pycache__' -prune -exec rm -rf {} +
COPY engine/fairsim /opt/fairsim/fairsim
# The system libraries everything links against, each at the path the loader
# uses (distroless is not merged-/usr), and their packages' records.
RUN set -eu; mkdir -p /out/root /out/root/var/lib/dpkg/status.d; \
    find /usr/local/bin/python3.12 /usr/local/lib/libpython3.12.so.1.0 /usr/local/lib/python3.12/lib-dynload /opt/site \
      -type f \( -name 'python3.12' -o -name '*.so' -o -name '*.so.*' \) \
      -exec ldd {} \; 2>/dev/null | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\/lib/ {print $1}' \
      | grep -v -e '^/usr/local/' -e '^/opt/' | sort -u > /tmp/libs; \
    for l in $(cat /tmp/libs); do \
      real="$(readlink -f "$l")"; \
      install -D -m 0755 "$real" "/out/root$l"; \
      pkg="$( (dpkg -S "$l" 2>/dev/null || dpkg -S "$real" 2>/dev/null || true) | head -1 | cut -d: -f1)"; \
      if [ -z "$pkg" ]; then echo "no package owns $l"; exit 1; fi; \
      dpkg -s "$pkg" > "/out/root/var/lib/dpkg/status.d/$pkg"; \
    done; \
    if grep -q -e libssl -e libcrypto /tmp/libs; then echo "OpenSSL in the engine image"; exit 1; fi
# The statistical validation suite (F-005 T-09, design §3.6) on what the image
# ships; the build fails unless every check passes, and the record goes into
# the image for Info, the startup self-check and the release manifest.
RUN mkdir -p /out/root/engine \
 && PYTHONPATH=/opt/fairsim:/opt/site PYTHONDONTWRITEBYTECODE=1 /usr/local/bin/python3.12 -m fairsim validate --out /out/root/engine/validation.json

FROM gcr.io/distroless/static-debian12:nonroot AS engine
COPY --from=engine-build /out/root/ /
COPY --from=engine-build /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=engine-build /usr/local/lib/libpython3.12.so.1.0 /usr/local/lib/libpython3.12.so.1.0
COPY --from=engine-build /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=engine-build /opt/site /opt/site
COPY --from=engine-build /opt/fairsim /opt/fairsim
ENV PATH=/usr/local/bin LD_LIBRARY_PATH=/usr/local/lib PYTHONPATH=/opt/fairsim:/opt/site \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python3.12", "-m", "fairsim"]
CMD ["info"]

FROM gcr.io/distroless/static-debian12:nonroot AS iam
COPY --from=build /out/iam /iam
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/iam"]
