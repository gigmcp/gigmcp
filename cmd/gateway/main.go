// Command gateway is the gigemcp walking skeleton: it seeds the echo server
// in the store, spawns each stored server in a bubblewrap sandbox, and
// serves an aggregated, bearer-authed streamable-HTTP MCP endpoint.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/gigemcp/gigemcp/internal/config"
	"github.com/gigemcp/gigemcp/internal/gateway"
	"github.com/gigemcp/gigemcp/internal/sandbox"
	"github.com/gigemcp/gigemcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.0-skeleton"

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if !sandbox.Available() {
		return fmt.Errorf("bwrap sandboxing unavailable: gigemcp requires Linux with bubblewrap installed")
	}

	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Skeleton: seed the single echo backend. Registry-driven installs
	// replace this in the manifests plan.
	if _, err := st.EnsureServer(ctx, "echo", cfg.EchoBinary); err != nil {
		return fmt.Errorf("seed echo server: %w", err)
	}

	servers, err := st.ListServers(ctx)
	if err != nil {
		return fmt.Errorf("list servers: %w", err)
	}

	var backends []gateway.Backend
	for _, srv := range servers {
		cmd := sandbox.Command(sandbox.Spec{
			Exec:   "/app/server",
			Mounts: []sandbox.Mount{{Src: srv.Binary, Dst: "/app/server"}},
		})
		client := mcp.NewClient(&mcp.Implementation{Name: "gigemcp-gw", Version: version}, nil)
		sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			return fmt.Errorf("connect backend %q: %w", srv.Name, err)
		}
		defer sess.Close()
		backends = append(backends, gateway.Backend{Name: srv.Name, Session: sess})
		log.Printf("backend %q running sandboxed (%s)", srv.Name, srv.Binary)
	}

	gw, err := gateway.New(ctx, version, backends)
	if err != nil {
		return err
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gw }, nil)
	log.Printf("gigemcp %s listening on %s (%d backend(s))", version, cfg.Listen, len(backends))
	return http.ListenAndServe(cfg.Listen, gateway.RequireBearer(cfg.BearerToken, handler))
}
