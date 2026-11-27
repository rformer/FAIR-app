# syntax=docker/dockerfile:1
# Hardened images for the platform services (F-001 T-00c, constitution S2/S5).
# One build stage; one final stage per binary, each holding only that binary:
#   docker build .                          iam (the default, last stage)
#   docker build --target posture .         posture service (F-015)
#   docker build --target posture-scanner . deployment drift scanner (F-015 T-27)
#   docker build --target fips-probe .      node FIPS probe (F-015 T-29)
#   docker build --target audit .           audit trail service (F-002 T-05), with /fair-audit-verify (T-10)
#   docker build --target risk .            risk data service (F-003 T-04)
#   docker build --target notify .          notification service (F-009 T-03)
#   docker build --target integrate .       integrate service, connectors (F-011 T-15)
#   docker build --target engine .          simulation engine, Python (F-005 T-04, ADR-013)
#   docker build --target engine-gate .     the engine's mTLS gate, Go FIPS (F-005 T-10)
#   docker build --target postgres|nats|openbao|versitygw|keycloak .
#                                           bundled dependencies (F-014 T-07; below)
# - FIPS 140-3: built with GOFIPS140=v1.0.0; go.mod sets fips140=on at runtime.
# - Static, CGO-free binary on distroless: no shell, no package manager.
# - Runs as non-root (65532) and works with a read-only root filesystem.
# - Base images pinned by digest (F-012 T-01); Dependabot keeps them current.
# - Reproducible (F-012 T-05): pass SOURCE_DATE_EPOCH (the commit time) and
#   VERSION, and export with rewrite-timestamp=true (scripts/repro-build.sh).

ARG PYTHON_IMAGE=python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS="-trimpath -buildvcs=false"
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
RUN for c in iam posture posture-scanner fips-probe gateway audit risk notify integrate engine-gate; do \
      go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/$c ./cmd/$c || exit 1; \
    done && \
    go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/fair-audit-verify ./cmd/audit-verify

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS fips-probe
COPY --from=build /out/fips-probe /fips-probe
USER 65532:65532
ENTRYPOINT ["/fips-probe"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS posture-scanner
COPY --from=build /out/posture-scanner /posture-scanner
USER 65532:65532
ENTRYPOINT ["/posture-scanner"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS posture
COPY --from=build /out/posture /posture
USER 65532:65532
EXPOSE 8443 9443
ENTRYPOINT ["/posture"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS audit
COPY --from=build /out/audit /audit
# The offline verifier (F-002 T-10), so air-gapped bundles carry it:
#   docker run --rm --entrypoint /fair-audit-verify -v "$PWD:/e:ro" <image> verify-export /e/bundle.zip
COPY --from=build /out/fair-audit-verify /fair-audit-verify
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/audit"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS risk
COPY --from=build /out/risk /risk
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/risk"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS notify
COPY --from=build /out/notify /notify
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/notify"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS integrate
COPY --from=build /out/integrate /integrate
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/integrate"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS engine-gate
COPY --from=build /out/engine-gate /engine-gate
USER 65532:65532
EXPOSE 8444 8081
ENTRYPOINT ["/engine-gate"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS gateway
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
# The validation record takes its time from the source date (F-012 T-05).
ARG SOURCE_DATE_EPOCH
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS engine
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

# ---------------------------------------------------------------------------
# Bundled dependencies (F-014 T-07; design §3.3, D-OQ3): the images the chart
# runs when the administrator chooses to bundle a dependency. Every upstream
# input is pinned in deploy/bundled/sources.json (tag, commit, SHA-256);
# each ADD names the same URL and checksum (internal/pincheck checks both).
#   docker build --target postgres .   PostgreSQL 16, OpenSSL FIPS provider 3.1.2 (CNPG operand)
#   docker build --target nats .       NATS server, rebuilt with the Go FIPS 140 module
#   docker build --target openbao .    OpenBao, rebuilt with the Go FIPS 140 module (no UI)
#   docker build --target versitygw .  versitygw (ADR-020), rebuilt with the Go FIPS 140 module
#   docker build --target keycloak .   Keycloak in FIPS strict mode with BC-FIPS
# The CloudNativePG operator is mirrored, not rebuilt (deploy/bundled/sources.json).
# Go components: GOFIPS140=v1.0.0, -trimpath, CGO_ENABLED=0, and fips140=on
# made the binary's default by a godebug line added to the upstream go.mod.

# The SPDX document of a component's pinned sources, for images whose
# sources a scanner cannot recognise in the binaries (the FIPS provider).
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS bundled-sbom
ENV CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS="-trimpath -buildvcs=false" GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/pincheck ./cmd/pincheck
COPY internal/pincheck ./internal/pincheck
COPY deploy/bundled/sources.json ./deploy/bundled/
RUN mkdir /out && go run ./cmd/pincheck -spdx postgres > /out/postgres.spdx.json

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS nats-build
ENV CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS="-trimpath -buildvcs=false" GOTOOLCHAIN=local
ADD --checksum=sha256:034a2a7535d67ae6f28962976a530dad1bd912dd2d9af05a3990f3b7e674008e https://github.com/nats-io/nats-server/archive/refs/tags/v2.15.3.tar.gz /tmp/src.tar.gz
WORKDIR /src
RUN tar -xzf /tmp/src.tar.gz --strip-components=1 \
 && go mod edit -godebug=fips140=on \
 && go mod download && go mod verify \
 && go build -ldflags "-s -w -X github.com/nats-io/nats-server/v2/server.gitCommit=2a9066eb57ff -X github.com/nats-io/nats-server/v2/server.serverVersion=v2.15.3" -o /out/nats-server . \
 && mkdir -p /out/licenses/nats-server && cp LICENSE /out/licenses/nats-server/

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS openbao-build
ENV CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS="-trimpath -buildvcs=false" GOTOOLCHAIN=local
ADD --checksum=sha256:610a4630e85fa754e6f3d5753a2c9122a575c043ad05165ab86126d4a556ef2f https://github.com/openbao/openbao/archive/refs/tags/v2.6.6.tar.gz /tmp/src.tar.gz
WORKDIR /src
# Without the "ui" tag: the bundled OpenBao is a key store for the platform,
# managed by fairctl and the CLI; the web UI is not shipped. Dependency
# security fixes not yet in an OpenBao release are applied by version
# (sources.json "overrides"), checked against the Go checksum database.
RUN tar -xzf /tmp/src.tar.gz --strip-components=1 \
 && go mod edit -godebug=fips140=on \
 && go get github.com/go-jose/go-jose/v4@v4.1.6 \
 && go mod download && go mod verify \
 && go build -ldflags "-s -w -X github.com/openbao/openbao/version.fullVersion=2.6.6 -X github.com/openbao/openbao/version.GitCommit=f8b155203a250347dc0866a3b615d44dbfec111f" -o /out/bao . \
 && mkdir -p /out/licenses/openbao && cp LICENSE /out/licenses/openbao/

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS versitygw-build
ENV CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS="-trimpath -buildvcs=false" GOTOOLCHAIN=local
ADD --checksum=sha256:97d35b99ce46c23c56723dbc46526de17b3b23e33b00e8044e9e3f420a3927c4 https://github.com/versity/versitygw/archive/refs/tags/v1.11.0.tar.gz /tmp/src.tar.gz
WORKDIR /src
RUN tar -xzf /tmp/src.tar.gz --strip-components=1 \
 && go mod edit -godebug=fips140=on \
 && go mod download && go mod verify \
 && go build -ldflags "-s -w -X main.Build=e42ae7ab8107 -X main.Version=v1.11.0" -o /out/versitygw ./cmd/versitygw \
 && mkdir -p /out/licenses/versitygw /out/root/var/lib/versitygw/data /out/root/var/lib/versitygw/versions /out/root/var/lib/versitygw/iam \
 && cp LICENSE /out/licenses/versitygw/ && (cp NOTICE /out/licenses/versitygw/ 2>/dev/null || true)

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS nats
COPY --from=nats-build /out/nats-server /nats-server
COPY --from=nats-build /out/licenses /licenses
USER 65532:65532
EXPOSE 4222 6222 8222
# The configuration (TLS with installation-CA certificates, JetStream) is
# mounted by the chart (T-08); without it the server refuses to start.
ENTRYPOINT ["/nats-server", "--config", "/etc/nats/nats.conf"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS openbao
COPY --from=openbao-build /out/bao /bao
COPY --from=openbao-build /out/licenses /licenses
USER 65532:65532
EXPOSE 8200 8201
ENTRYPOINT ["/bao", "server", "-config=/openbao/config"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS versitygw
COPY --from=versitygw-build /out/versitygw /versitygw
COPY --from=versitygw-build /out/licenses /licenses
COPY --from=versitygw-build --chown=65532:65532 /out/root/var/lib/versitygw /var/lib/versitygw
USER 65532:65532
EXPOSE 7070
# TLS is not optional: without the mounted certificate it refuses to start.
# The POSIX backend with versioning (Object Lock needs it) under
# /var/lib/versitygw, the encrypted volume in the chart (ADR-020); iam/ there
# holds the per-service accounts when the chart selects the internal IAM
# backend (--iam-dir, T-08).
ENTRYPOINT ["/versitygw", "--cert", "/etc/versitygw/tls/tls.crt", "--key", "/etc/versitygw/tls/tls.key"]
CMD ["posix", "--versioning-dir", "/var/lib/versitygw/versions", "/var/lib/versitygw/data"]

# PostgreSQL 16 for CloudNativePG (D-OQ2, D-OQ3). The cryptography is the
# OpenSSL FIPS provider 3.1.2 (CMVP #4985, FIPS 140-3), built from its
# validated source as its Security Policy requires and installed with its own
# fipsinstall; the libraries around it are OpenSSL 3.5 (LTS), which loads it.
# openssl.cnf activates only the FIPS and base providers and makes fips=yes
# the default property, with config_diagnostics so a provider that fails its
# integrity check or self-tests (run at every load: -self_test_onload, the
# 3.1 default) stops OpenSSL, and so PostgreSQL, from starting. Built without
# ICU, readline or zlib, so glibc is the only other library. PostgreSQL's
# initdb, pg_ctl and archive_command run through /bin/sh, so the image keeps
# dash as /bin/sh (and nothing else of a shell or package manager).
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS postgres-build
ARG SOURCE_DATE_EPOCH
ADD --checksum=sha256:603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz /tmp/openssl.tar.gz
ADD --checksum=sha256:a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539 https://github.com/openssl/openssl/releases/download/openssl-3.1.2/openssl-3.1.2.tar.gz /tmp/openssl-fips.tar.gz
ADD --checksum=sha256:3e930f3366f675ab26e873d16201201f8e9b6d9bc13686e4465380271145ea2d https://ftp.postgresql.org/pub/source/v16.16/postgresql-16.16.tar.gz /tmp/postgresql.tar.gz
RUN set -eu; mkdir -p /build/openssl /build/fips /build/pg; \
    tar -xzf /tmp/openssl.tar.gz -C /build/openssl --strip-components=1; \
    tar -xzf /tmp/openssl-fips.tar.gz -C /build/fips --strip-components=1; \
    tar -xzf /tmp/postgresql.tar.gz -C /build/pg --strip-components=1
WORKDIR /build/openssl
RUN ./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl --libdir=lib shared no-tests no-docs \
      '-Wl,-rpath,/usr/local/ssl/lib' \
 && make -j"$(nproc)" >/dev/null && make install_sw install_ssldirs >/dev/null
WORKDIR /build/fips
RUN ./Configure enable-fips --prefix=/usr/local/ssl --openssldir=/usr/local/ssl --libdir=lib shared no-tests \
 && make -j"$(nproc)" >/dev/null && make install_fips \
 && test -f /usr/local/ssl/lib/ossl-modules/fips.so && test -f /usr/local/ssl/fipsmodule.cnf
COPY <<'EOF' /usr/local/ssl/openssl.cnf
# F-014 T-07: only the FIPS provider (3.1.2) and the base provider (encoders
# and decoders, no algorithms); fips=yes for every fetch. A provider that
# cannot load or fails its self-tests is an error, not a fallback.
config_diagnostics = 1
openssl_conf = openssl_init

.include /usr/local/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
EOF
WORKDIR /build/pg
RUN ./configure --prefix=/usr/lib/postgresql/16 --with-openssl --without-icu --without-readline --without-zlib \
      --with-system-tzdata=/usr/share/zoneinfo \
      --with-includes=/usr/local/ssl/include --with-libraries=/usr/local/ssl/lib \
      LDFLAGS="-Wl,-rpath,/usr/local/ssl/lib" >/dev/null \
 && make -j"$(nproc)" world-bin >/dev/null && make install-strip >/dev/null \
 && make -C contrib/pgcrypto install-strip >/dev/null
# The image's root: the PostgreSQL and OpenSSL trees without headers,
# static libraries or manuals; dash as /bin/sh with its dpkg record; the
# licences. The provider must be the 3.1.2 build and OpenSSL must refuse MD5.
RUN set -eu; r=/out/root; mkdir -p $r/usr/local $r/usr/lib $r/bin $r/var/lib/dpkg/status.d $r/licenses/openssl $r/licenses/openssl-fips-provider $r/licenses/postgresql; \
    cp -a /usr/local/ssl $r/usr/local/ssl; rm -rf $r/usr/local/ssl/include $r/usr/local/ssl/lib/*.a $r/usr/local/ssl/lib/pkgconfig $r/usr/local/ssl/lib/cmake $r/usr/local/ssl/misc $r/usr/local/ssl/*.dist $r/usr/local/ssl/certs $r/usr/local/ssl/private; \
    cp -a /usr/lib/postgresql $r/usr/lib/postgresql; rm -rf $r/usr/lib/postgresql/16/include $r/usr/lib/postgresql/16/lib/*.a $r/usr/lib/postgresql/16/lib/pgxs $r/usr/lib/postgresql/16/lib/pkgconfig; \
    cp /bin/dash $r/bin/sh; dpkg -s dash > $r/var/lib/dpkg/status.d/dash; \
    cp /build/openssl/LICENSE.txt $r/licenses/openssl/; cp /build/fips/LICENSE.txt $r/licenses/openssl-fips-provider/; cp /build/pg/COPYRIGHT $r/licenses/postgresql/; \
    $r/usr/local/ssl/bin/openssl list -providers | tee /tmp/providers; \
    grep -A3 '^  fips' /tmp/providers | grep -q 'version: 3.1.2' && grep -A3 '^  fips' /tmp/providers | grep -q 'status: active'; \
    if echo x | $r/usr/local/ssl/bin/openssl dgst -md5 >/dev/null 2>&1; then echo "MD5 available: not in FIPS mode"; exit 1; fi; \
    ldd $r/usr/lib/postgresql/16/bin/postgres | grep -q '/usr/local/ssl/lib/libssl.so.3'; \
    if ldd $r/usr/lib/postgresql/16/bin/postgres | grep -E 'libz|libicu|libreadline|/usr/lib/x86_64-linux-gnu/libssl|/usr/lib/x86_64-linux-gnu/libcrypto'; then exit 1; fi

FROM gcr.io/distroless/base-nossl-debian12:nonroot@sha256:be40c00dfabd86576d92666e87e406714d5618342de1a0c213ad232de255172e AS postgres
COPY --from=postgres-build /out/root/ /
COPY --from=bundled-sbom /out/postgres.spdx.json /usr/share/doc/fair/sbom/postgres.spdx.json
ENV PATH=/usr/lib/postgresql/16/bin:/usr/local/ssl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# CloudNativePG runs its instance manager in this image (Cluster spec
# postgresUID/postgresGID 65532, T-08) and starts PostgreSQL itself.
USER 65532:65532
EXPOSE 5432
ENTRYPOINT ["/usr/lib/postgresql/16/bin/postgres"]

# Keycloak in FIPS strict mode (Keycloak's FIPS guide): the BC-FIPS jars in
# providers/ and the server built with --features=fips --fips-mode=strict, on
# Keycloak's own Red Hat UBI 9 image, whose OpenJDK follows the host's FIPS
# mode (FIPS-JVM enabled on a FIPS node). The jars are Keycloak 26.8.2's
# tested versions; bc-fips 2.1.3 is a CMVP patch release of the module on
# certificate #4943 (FIPS 140-3; listed version 2.1.1), and fixes CVEs in
# 2.1.1 (deploy/bundled/sources.json). The upstream image carries bash
# (kc.sh) and coreutils but no package manager. Not bit-for-bit reproducible:
# Keycloak's build step (Quarkus augmentation) generates bytecode whose
# content varies between runs, so scripts/repro-build.sh leaves it out.
FROM quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3 AS keycloak-build
ADD --chmod=0644 --checksum=sha256:f55fc476ede820d5c03fe87e6ced5bb0095e1dc30b387445846a3ff0274f8c0e https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.1.3/bc-fips-2.1.3.jar /opt/keycloak/providers/
ADD --chmod=0644 --checksum=sha256:af604aa5b337725872651067a819ebc03aa298685572b0b2ad5343c786faad0a https://repo1.maven.org/maven2/org/bouncycastle/bctls-fips/2.1.25/bctls-fips-2.1.25.jar /opt/keycloak/providers/
ADD --chmod=0644 --checksum=sha256:cf161ba2f6b4505816f4661663b3e0771184a50ee5b178a0018c817b336f0e5c https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-fips/2.1.13/bcpkix-fips-2.1.13.jar /opt/keycloak/providers/
ADD --chmod=0644 --checksum=sha256:f44904f61552c823bcc3686a24052ee3135212d547754eaa2ff6532e210103cb https://repo1.maven.org/maven2/org/bouncycastle/bcutil-fips/2.1.8/bcutil-fips-2.1.8.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build --features=fips --fips-mode=strict --db=postgres --health-enabled=true --metrics-enabled=true

FROM quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3 AS keycloak
COPY --from=keycloak-build /opt/keycloak/ /opt/keycloak/
# BC-FIPS 2.1 would otherwise load its optional native code from /tmp; the
# validated module is the pure-Java one (certificate #4943), so it is kept to
# that, and nothing needs an executable /tmp.
ENV JAVA_OPTS_APPEND="-Dorg.bouncycastle.native.cpu_variant=java"
USER 65532:65532
EXPOSE 8443 9000
# Without a hostname and the HTTPS key store (BCFKS in strict mode) it
# refuses to start; the chart (T-08) mounts both and the realm.
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS iam
COPY --from=build /out/iam /iam
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/iam"]
