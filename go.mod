module github.com/rformer/fair-app

go 1.24

// Constitution S2: FIPS 140-validated cryptography. Binaries are built with
// GOFIPS140=v1.0.0 (see Makefile/Dockerfile) and run with the FIPS module on.
godebug fips140=on

require github.com/jackc/pgx/v5 v5.7.5

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)
