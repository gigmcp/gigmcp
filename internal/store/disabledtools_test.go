package store

import (
	"context"
	"testing"
)

func TestDisabledToolsLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// Default: nothing disabled.
	got, err := st.ListDisabledTools(ctx, "slack")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("fresh app must have no disabled tools, got %v", got)
	}

	// Disable a tool (enabled=false) → it appears.
	if err := st.SetToolEnabled(ctx, "slack", "admin", false); err != nil {
		t.Fatal(err)
	}
	got, err = st.ListDisabledTools(ctx, "slack")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "admin" {
		t.Fatalf("want [admin], got %v", got)
	}

	// Idempotent double-disable.
	if err := st.SetToolEnabled(ctx, "slack", "admin", false); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ListDisabledTools(ctx, "slack")
	if len(got) != 1 {
		t.Fatalf("double-disable must stay 1 row, got %v", got)
	}

	// Disable a second tool → sorted output.
	if err := st.SetToolEnabled(ctx, "slack", "ban", false); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ListDisabledTools(ctx, "slack")
	if len(got) != 2 || got[0] != "admin" || got[1] != "ban" {
		t.Fatalf("want sorted [admin ban], got %v", got)
	}

	// Re-enable (enabled=true) removes it.
	if err := st.SetToolEnabled(ctx, "slack", "admin", true); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ListDisabledTools(ctx, "slack")
	if len(got) != 1 || got[0] != "ban" {
		t.Fatalf("re-enable must leave [ban], got %v", got)
	}

	// Re-enable a tool that isn't disabled is a noop.
	if err := st.SetToolEnabled(ctx, "slack", "never-disabled", true); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ListDisabledTools(ctx, "slack")
	if len(got) != 1 || got[0] != "ban" {
		t.Fatalf("noop re-enable changed state: %v", got)
	}
}

func TestDisabledToolsPerServerIsolation(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if err := st.SetToolEnabled(ctx, "slack", "admin", false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetToolEnabled(ctx, "gmail", "send", false); err != nil {
		t.Fatal(err)
	}

	slack, _ := st.ListDisabledTools(ctx, "slack")
	if len(slack) != 1 || slack[0] != "admin" {
		t.Fatalf("slack: want [admin], got %v", slack)
	}
	gmail, _ := st.ListDisabledTools(ctx, "gmail")
	if len(gmail) != 1 || gmail[0] != "send" {
		t.Fatalf("gmail: want [send], got %v", gmail)
	}
}

func TestDeleteDisabledToolsForServer(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if err := st.SetToolEnabled(ctx, "slack", "admin", false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetToolEnabled(ctx, "slack", "ban", false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetToolEnabled(ctx, "gmail", "send", false); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteDisabledToolsForServer(ctx, "slack"); err != nil {
		t.Fatal(err)
	}
	slack, _ := st.ListDisabledTools(ctx, "slack")
	if len(slack) != 0 {
		t.Fatalf("slack disabled tools must be cleared, got %v", slack)
	}
	// Other servers untouched.
	gmail, _ := st.ListDisabledTools(ctx, "gmail")
	if len(gmail) != 1 || gmail[0] != "send" {
		t.Fatalf("gmail must be untouched, got %v", gmail)
	}

	// Idempotent: deleting again is a noop.
	if err := st.DeleteDisabledToolsForServer(ctx, "slack"); err != nil {
		t.Fatal(err)
	}
}
