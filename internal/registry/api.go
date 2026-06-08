package registry

import (
	"context"

	"github.com/gigmcp/gigmcp/internal/store"
)

// Installer is the install seam consumed by the REST API. Record-only:
// Install never spawns; the gateway run-loop owns spawning.
type Installer interface {
	// Install resolves ref (name@version | name = latest | sha256:<digest>),
	// pulls + verifies + extracts the pinned image, and records the server +
	// manifest. Idempotent by (name, version, manifest hash).
	Install(ctx context.Context, ref string) (store.Server, error)
	// Uninstall removes the server's store rows and extracted files.
	Uninstall(ctx context.Context, name string) error
	// List returns all registered servers.
	List(ctx context.Context) ([]store.Server, error)
}
