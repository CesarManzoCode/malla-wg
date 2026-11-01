# Single check command (kiln check_command and CI): format, vet and tests.
# Before the Go module exists (K0) it only reports that there is nothing to check.
.PHONY: check vectors test-unpriv

check:
	@if [ ! -f go.mod ]; then echo "check: no Go module yet"; exit 0; fi; \
	unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi; \
	go vet ./... && go test -short -count=1 ./...

# Criterion 1 and 2 of the contract: RFC and Wycheproof vectors of the own primitives.
vectors:
	go test -count=1 -run '^(TestCritVectors.*|TestCritWycheproof.*)$$' ./internal/x25519 ./internal/chachapoly ./internal/blake2s ./internal/hkdf

# Criterion 32 of the contract: the whole suite, through critrun, inside the
# unprivileged environment of §8 (no network or user namespaces, no
# capabilities) and without network access to modules. critrun exits 77 if
# the only tests not passed are needs-privilege skips. It is built first and
# run as a binary because `go run` turns any non-zero exit into 1.
test-unpriv:
	bin="$$(mktemp -d)/critrun" && go build -o "$$bin" ./verify/critrun && \
	unshare -rU sh -c 'echo 0 > /proc/sys/user/max_user_namespaces; exec setpriv --securebits +noroot,+noroot_locked,+no_setuid_fixup,+no_setuid_fixup_locked --bounding-set -all --inh-caps -all --ambient-caps -all -- env GOFLAGS=-mod=mod GOPROXY=off "$$0" -count=1 ./...' "$$bin"
