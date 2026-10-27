#!/usr/bin/env bash
# Regenerates internal/api from api/proto (F-015 T-27). Generated code is
# committed; run this after changing a .proto, from the repository root:
#   docker run --rm -v "$PWD:/src" -w /src golang:1.24-bookworm scripts/gen-proto.sh
set -euo pipefail
PROTOC_GEN_GO=v1.36.6
PROTOC_GEN_GO_GRPC=v1.5.1
if ! command -v protoc >/dev/null; then
  apt-get update -qq && apt-get install -y -qq protobuf-compiler >/dev/null
fi
GOBIN=/tmp/protoc-bin go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO}"
GOBIN=/tmp/protoc-bin go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC}"
export PATH="/tmp/protoc-bin:$PATH"
protoc -I api/proto \
  --go_out=. --go_opt=module=github.com/rformer/fair-app \
  --go-grpc_out=. --go-grpc_opt=module=github.com/rformer/fair-app \
  $(find api/proto -name '*.proto' | sort)
