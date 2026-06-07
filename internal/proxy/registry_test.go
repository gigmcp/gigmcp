package proxy_test

import (
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
)

func TestRegistryLookupByIP(t *testing.T) {
	r := proxy.NewRegistry()
	id := proxy.Identity{Server: "github", Tenant: "alice"}
	r.Bind("10.88.0.2", id)
	got, ok := r.Lookup("10.88.0.2")
	if !ok || got != id {
		t.Fatalf("lookup: %+v ok=%v", got, ok)
	}
	if _, ok := r.Lookup("10.88.0.6"); ok {
		t.Fatal("unknown IP should not resolve")
	}
	r.Unbind("10.88.0.2")
	if _, ok := r.Lookup("10.88.0.2"); ok {
		t.Fatal("unbound IP should not resolve")
	}
}
