package store

import (
	"context"
	"testing"
)

func TestUserInstalls(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if got, err := st.ListUserInstalls(ctx, 1); err != nil || len(got) != 0 {
		t.Fatalf("empty: got %v err %v", got, err)
	}
	if err := st.InstallForUser(ctx, 1, "gmail"); err != nil {
		t.Fatal(err)
	}
	if err := st.InstallForUser(ctx, 1, "gmail"); err != nil { // idempotent
		t.Fatalf("re-install must be idempotent: %v", err)
	}
	ok, err := st.IsUserInstalled(ctx, 1, "gmail")
	if err != nil || !ok {
		t.Fatalf("IsUserInstalled gmail: %v %v", ok, err)
	}
	if ok, _ := st.IsUserInstalled(ctx, 2, "gmail"); ok { // isolation
		t.Fatal("user 2 must not see user 1 install")
	}
	if err := st.UninstallForUser(ctx, 1, "gmail"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ListUserInstalls(ctx, 1); len(got) != 0 {
		t.Fatalf("after uninstall: %v", got)
	}
}
