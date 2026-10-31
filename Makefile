# Single check command (kiln check_command and CI): format, vet and tests.
# Before the Go module exists (K0) it only reports that there is nothing to check.
.PHONY: check

check:
	@if [ ! -f go.mod ]; then echo "check: no Go module yet"; exit 0; fi; \
	unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi; \
	go vet ./... && go test -short -count=1 ./...
