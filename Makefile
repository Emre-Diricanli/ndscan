BINARY=ndscan

.PHONY: build tidy clean

tidy:
	go mod tidy

build: tidy
	go build -o $(BINARY) ./cmd/ndscan

clean:
	rm -f $(BINARY)
