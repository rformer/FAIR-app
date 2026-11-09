export GOFIPS140 ?= v1.0.0
export CGO_ENABLED ?= 0

.PHONY: build test test-db test-stride migrate lint fmt vet image clean

build:
	go build -trimpath -o bin/iam ./cmd/iam

test:
	CGO_ENABLED=1 go test -race -count=1 ./...

# Requires PostgreSQL 16+ and psql. Provide an admin connection via libpq vars, e.g.
#   make test-db PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=...
# Worker tests also need a JetStream server: FAIR_TEST_NATS=nats://localhost:4222.
# The T-08 scale test runs only with FAIR_TEST_SCALE=1 (slow).
test-db:
	FAIR_TEST_PG=1 go test -count=1 -timeout 60m -v ./db/tests/

# The STRIDE suites of F-015 (T-36, design §8), F-001 (T-40, design §7) and
# F-002 (T-21, design §8) and F-003 (T-15, design §8),
# with the database (as test-db). db/tests TestSTRIDECatalog checks that every
# threat maps to tests and that each of them is run here.
STRIDE_DB_TESTS = TestSTRIDE|TestPostureImportSigned|TestPostureNoDirectWrites|TestPostureDirectEditDetected|TestDriftDetectsDirectDBEdit|TestApprovalLifecycle|TestPostureAPIRestrictedBUHidden|TestRevertFaultInjection|TestDriftExceptionsAndMissedRevert|TestSecOpsSaaSNotifiesWeakening|TestExceptionDuration|TestRevertOnExpiry|TestScannerChannelAuthentication|TestSAMLLoginEndToEnd|TestLoginTicketRedemption|TestGatewaySessionCookieAndStorage|TestGatewayTimeouts|TestGatewayRevocation|TestGatewayCSRF|TestNetworkBinding|TestGatewayProxy|TestServiceAccountMTLS|TestDBContextScopesRows|TestDBContextFailsClosed|TestRLSHarness|TestAppRoleCannotBypassRLS|TestGrantSnapshotNeedsValidContext|TestScopeForms|TestNewestQuery|TestAssignmentEscalationSuite|TestCustomRole|TestSoDBlocksCustomRolesUnlessExcepted|TestAccessReviews|TestApprovalSecondAdmin|TestIDPRoutingByDomain|TestSCIMListing|TestUserAdminVisibility|TestRollupLeakage|TestRestrictedBUAdministration|TestEntitlementReport|TestSCIMBulk|TestBreakglass|TestIdPOutageRecoveryDrill|TestAssignmentScope|TestGroupMappingConflictsAndAuthority|TestAuditSubmit|TestAuditSequenceAppendRefusesForgeries|TestAuditAppendOnly|TestAuditSchemaAccess|TestAuditVerificationFindsTampering|TestAuditCheckpointCloseRefusesForgeries|TestAuditCheckpointWORMCopies|TestAuditVerificationCopiesAndArchives|TestAuditForwardSyslog|TestAuditArchive|TestAuditExportBundle|TestAuditReadsAreRecorded|TestAuditHoldAPI|TestAuditReadVisibility|TestAuditExportScope|TestAuditIntakeWaitsForTheSequencer|TestAuditCapacity|TestAuditForwardBacklogAlert|TestAccessReviews|TestDriftExceptionExpiryAgainstTrail|TestAuditApprovalEvidencePosture|TestRiskVersions|TestRiskAppendOnly|TestRiskBundle|TestRiskValidationParity|TestRiskPins|TestRiskAuditEvents|TestRiskScenariosAPI|TestInheritedRead|TestRiskMoveAndArchive|TestRiskExportImport|TestRiskSecretsRefused|TestRiskLimits
STRIDE_UNIT_TESTS = TestVerifyRelease|TestPackagesSignedReleaseTamper|TestScannerRBACIsReadOnlyAndMatchesAccess|TestPermissionManifest|TestScannerPodHardenedAndEgressRestricted|TestNegativeCorpus|TestNameIDCommentInjection|TestReplayAndRequestSingleUse|TestTicket|TestDiscoveryRateLimit|TestRateLimitPerToken|TestCatalogMatchesCode|TestOpenAPIMatchesRoutes|TestTamperingIsDetected|TestCompare|TestArchiveTamperCorpus|TestNoSecretsInEvents
test-stride:
	go test -count=1 -run '^($(STRIDE_UNIT_TESTS))$$' ./internal/profilepkg/ ./internal/profilegen/ ./internal/scanner/ ./internal/authn/saml/ ./internal/authn/ ./internal/scim/ ./pkg/audit/ ./internal/iamapi/ ./internal/audit/integrity/ ./internal/audit/evidence/
	FAIR_TEST_PG=1 go test -count=1 -timeout 30m -v -run '^($(STRIDE_DB_TESTS))' ./db/tests/

# Applies the embedded migrations and release catalog as app_migrator (T-02b).
# Needs PGDATABASE, FAIR_MIGRATOR_PASSWORD_FILE and libpq connection vars;
# FAIR_ENV=development locally (production requires PGSSLMODE=verify-full).
migrate: build
	./bin/iam migrate

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run

image:
	docker build -t fair-iam:dev .

clean:
	rm -rf bin coverage.out
