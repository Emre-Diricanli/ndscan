# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build

ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/ndscan \
    ./cmd/ndscan

FROM alpine:3.22

# Alpine provides the wget used by HEALTHCHECK. nmap is deliberately omitted:
# the web UI's default fast scan path is native, and including nmap would make
# the runtime image substantially larger.
RUN addgroup -S ndscan && adduser -S -G ndscan ndscan

COPY --from=build /out/ndscan /usr/local/bin/ndscan

USER ndscan
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/api/state || exit 1

ENTRYPOINT ["ndscan"]
CMD ["web"]
