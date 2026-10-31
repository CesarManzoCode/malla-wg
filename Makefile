# Single check command (kiln check_command and CI): format, vet and tests.
# Before the Go module exists (K0) it only reports that there is nothing to check.
.PHONY: check vectors

check:
	@if [ ! -f go.mod ]; then echo "check: no Go module yet"; exit 0; fi; \
	unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi; \
	go vet ./... && go test -short -count=1 ./...

# Criterion 1 and 2 of the contract: RFC and Wycheproof vectors of the own primitives.
vectors:
	go test -count=1 -run '^(TestCritVectors.*|TestCritWycheproof.*)$$' ./internal/x25519 ./internal/chachapoly ./internal/blake2s ./internal/hkdf
