module github.com/rformer/fair-app

go 1.26.10

// Constitution S2: FIPS 140-validated cryptography. Binaries are built with
// GOFIPS140=v1.0.0 (see Makefile/Dockerfile) and run with the FIPS module on.
godebug fips140=on

require (
	github.com/beevik/etree v1.7.0
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/defenseunicorns/go-oscal v0.7.2
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.12.0
	github.com/minio/minio-go/v7 v7.4.1
	github.com/nats-io/nats.go v1.47.0
	github.com/riverqueue/river v0.30.0
	github.com/riverqueue/river/riverdriver/riverpgxv5 v0.30.0
	github.com/russellhaering/gosaml2 v0.12.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	go.opentelemetry.io/proto/otlp v1.11.1
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/oauth2 v0.37.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.31.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/riverqueue/river/riverdriver v0.30.0 // indirect
	github.com/riverqueue/river/rivershared v0.30.0 // indirect
	github.com/riverqueue/river/rivertype v0.30.0 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
)
