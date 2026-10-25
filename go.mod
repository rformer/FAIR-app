module github.com/rformer/fair-app

go 1.24

// Constitution S2: FIPS 140-validated cryptography. Binaries are built with
// GOFIPS140=v1.0.0 (see Makefile/Dockerfile) and run with the FIPS module on.
godebug (
	fips140=on
)
