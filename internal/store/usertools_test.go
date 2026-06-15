package store

import (
	"context"
	"testing"
)

func TestUserDisabledTools(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if d, err := st.ListUserDisabledTools(ctx, 1, "gmail"); err != nil || len(d) != 0 {
		t.Fatalf("default empty: %v %v", d, err)
	}
	if err := st.SetUserToolEnabled(ctx, 1, "gmail", "send", false); err != nil { // disable
		t.Fatal(err)
	}
	d, _ := st.ListUserDisabledTools(ctx, 1, "gmail")
	if len(d) != 1 || d[0] != "send" {
		t.Fatalf("expected [send], got %v", d)
	}
	if d2, _ := st.ListUserDisabledTools(ctx, 2, "gmail"); len(d2) != 0 { // isolation
		t.Fatalf("user 2 isolation: %v", d2)
	}
	if err := st.SetUserToolEnabled(ctx, 1, "gmail", "send", true); err != nil { // re-enable removes row
		t.Fatal(err)
	}
	if d3, _ := st.ListUserDisabledTools(ctx, 1, "gmail"); len(d3) != 0 {
		t.Fatalf("after enable: %v", d3)
	}
}
