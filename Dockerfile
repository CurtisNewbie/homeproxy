# syntax=docker/dockerfile:1

# Build stage: the module declares `go 1.24.4`, so the builder must be at least that.
FROM golang:1.24.4 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/homeproxy .

# Runtime stage: no shell, no package manager, non-root by default.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/homeproxy /usr/local/bin/homeproxy

WORKDIR /
USER nonroot:nonroot

# Proxy port only. The management port (server.port, default 7990) stays inside
# the container network and is never published.
EXPOSE 17890

# The config file is mounted at runtime, e.g. -v ./conf-prod.yml:/conf/conf.yml:ro.
# miso reads CLI-style "key=value" arguments, so the config path is passed this way.
ENTRYPOINT ["/usr/local/bin/homeproxy"]
CMD ["configFile=/conf/conf.yml"]
