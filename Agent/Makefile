.PHONY: deps build build-govpp run clean

# Fetch/verify all dependencies (required after adding modernc.org/sqlite)
deps:
	GOTOOLCHAIN=auto go mod tidy

# Build without VPP support (memory backend only)
build: deps
	GOTOOLCHAIN=auto go build -o bin/tlsctrl-agent ./cmd/tlsctrl-agent

# Build with full VPP/GovPP support (requires VPP binary API bindings)
build-govpp: deps
	GOTOOLCHAIN=auto go build -tags govpp -o bin/tlsctrl-agent ./cmd/tlsctrl-agent

run: build
	./bin/tlsctrl-agent

clean:
	rm -f bin/tlsctrl-agent
