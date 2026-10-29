module github.com/rformer/fair-app

go 1.26.0

// Constitution S2: FIPS 140-validated cryptography. Binaries are built with
// GOFIPS140=v1.0.0 (see Makefile/Dockerfile) and run with the FIPS module on.
godebug fips140=on

require (
	github.com/beevik/etree v1.7.0
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/defenseunicorns/go-oscal v0.7.2
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/jackc/pgx/v5 v5.8.0
	github.com/nats-io/nats.go v1.47.0
	github.com/riverqueue/river v0.30.0
	github.com/riverqueue/river/riverdriver/riverpgxv5 v0.30.0
	github.com/russellhaering/gosaml2 v0.12.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/oauth2 v0.37.0
	google.golang.org/grpc v1.74.2
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/riverqueue/river/riverdriver v0.30.0 // indirect
	github.com/riverqueue/river/rivershared v0.30.0 // indirect
	github.com/riverqueue/river/rivertype v0.30.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
