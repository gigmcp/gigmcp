FROM golang:1.26.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build all production binaries as static CGO_ENABLED=0.
# bootstrap is the trusted in-sandbox init (required for egress sandboxes;
# mounted into each bwrap child and executed as the entrypoint before the
# untrusted server).
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 go build -o /out/echo-mcp ./cmd/echo-mcp \
 && CGO_ENABLED=0 go build -o /out/bootstrap ./cmd/bootstrap

# Not FROM scratch: the runtime needs bwrap (DESIGN.md §3) and iptables
# (gateway's applyForwardDrop sets FORWARD policy to DROP at startup — see C
# in the hardening notes). ca-certificates for TLS to external APIs.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap ca-certificates iptables \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gateway /usr/local/bin/gateway
COPY --from=build /out/echo-mcp /usr/local/bin/echo-mcp
# bootstrap is the trusted in-sandbox init binary; it is bind-mounted into each
# egress sandbox at GIG_BOOTSTRAP_PATH (default /usr/local/bin/bootstrap).
COPY --from=build /out/bootstrap /usr/local/bin/bootstrap
ENV GIG_ECHO_BIN=/usr/local/bin/echo-mcp \
    GIG_DB_PATH=/data/gigmcp.db \
    GIG_BOOTSTRAP_PATH=/usr/local/bin/bootstrap
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["gateway"]
