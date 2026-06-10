BINARY=ndscan
VERSION?=0.1.0
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build tidy clean install

tidy:
	go mod tidy

build: tidy
	go build $(LDFLAGS) -o $(BINARY) ./cmd/ndscan

# Installs to $(go env GOPATH)/bin — make sure that's on your PATH.
install: tidy
	go install $(LDFLAGS) ./cmd/ndscan

clean:
	rm -f $(BINARY)
