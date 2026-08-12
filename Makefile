BINARY=ndscan
VERSION?=0.1.0
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: fmt vet test check build tidy clean install release snapshot goreleaser-check

fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	go vet ./...

test:
	go test -race ./...

check: fmt vet build test

tidy:
	go mod tidy

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/ndscan

# Local development install (puts it in your Go bin, not necessarily global)
install: tidy
	go install $(LDFLAGS) ./cmd/ndscan

clean:
	rm -f $(BINARY)

# --- Release helpers ---

# Check that goreleaser is available
goreleaser-check:
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "goreleaser is not installed. Install it with:"; \
		echo "  brew install goreleaser"; \
		echo "  or see https://goreleaser.com/install/"; \
		exit 1; \
	}

# Create a new release (tags + builds + publishes to GitHub)
# Usage:
#   make release VERSION=v0.2.0
# This will:
#   1. Create and push the git tag
#   2. Run goreleaser which builds binaries for darwin/linux + amd64/arm64
#      and creates a GitHub Release
release: check goreleaser-check
	@if [ "$(VERSION)" = "0.1.0" ]; then \
		echo "Please specify a version: make release VERSION=v0.2.0"; \
		exit 1; \
	fi
	@echo "==> Creating release $(VERSION)"
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@if ! goreleaser release --clean; then \
		git push --delete origin $(VERSION); \
		git tag --delete $(VERSION); \
		exit 1; \
	fi

# Build release artifacts locally (without publishing) for testing
snapshot: tidy goreleaser-check
	goreleaser release --snapshot --clean
	@echo "==> Snapshot artifacts are in ./dist/"
