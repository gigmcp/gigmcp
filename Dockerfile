FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 go build -o /out/echo-mcp ./cmd/echo-mcp

# Not FROM scratch: the runtime needs the bwrap binary (DESIGN.md §3).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gateway /usr/local/bin/gateway
COPY --from=build /out/echo-mcp /usr/local/bin/echo-mcp
ENV GIGE_ECHO_BIN=/usr/local/bin/echo-mcp \
    GIGE_DB_PATH=/data/gigemcp.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["gateway"]
