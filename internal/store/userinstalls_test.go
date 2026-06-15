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

func TestUninstallForUserCascadesPerUser(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// User 1 installs gmail, disables a tool, and adds gmail to one of their profiles.
	if err := st.InstallForUser(ctx, 1, "gmail"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserToolEnabled(ctx, 1, "gmail", "send", false); err != nil {
		t.Fatal(err)
	}
	p1, err := st.CreateProfile(ctx, "u1-prof", "U1 Profile", 1, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p1.ID, []string{"gmail"}); err != nil {
		t.Fatal(err)
	}

	// User 2 also installs gmail, disables a tool, and adds it to their own profile.
	if err := st.InstallForUser(ctx, 2, "gmail"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserToolEnabled(ctx, 2, "gmail", "send", false); err != nil {
		t.Fatal(err)
	}
	p2, err := st.CreateProfile(ctx, "u2-prof", "U2 Profile", 2, "hash2")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p2.ID, []string{"gmail"}); err != nil {
		t.Fatal(err)
	}

	// Uninstall for user 1 only.
	if err := st.UninstallForUser(ctx, 1, "gmail"); err != nil {
		t.Fatal(err)
	}

	// User 1: install row, tool prefs, and profile membership all cleared.
	if ok, _ := st.IsUserInstalled(ctx, 1, "gmail"); ok {
		t.Fatal("user 1 install not removed")
	}
	if d, _ := st.ListUserDisabledTools(ctx, 1, "gmail"); len(d) != 0 {
		t.Fatalf("user 1 tool prefs not cleared: %v", d)
	}
	if srvs, _ := st.GetProfileServers(ctx, p1.ID); len(srvs) != 0 {
		t.Fatalf("user 1 profile_servers not cleared: %v", srvs)
	}

	// User 2: everything untouched.
	if ok, _ := st.IsUserInstalled(ctx, 2, "gmail"); !ok {
		t.Fatal("user 2 install must be untouched")
	}
	if d, _ := st.ListUserDisabledTools(ctx, 2, "gmail"); len(d) != 1 {
		t.Fatalf("user 2 tool prefs must be untouched: %v", d)
	}
	if srvs, _ := st.GetProfileServers(ctx, p2.ID); len(srvs) != 1 {
		t.Fatalf("user 2 profile_servers must be untouched: %v", srvs)
	}
}

func TestCascadeRemoveServer(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	_ = st.InstallForUser(ctx, 1, "gmail")
	_ = st.InstallForUser(ctx, 2, "gmail")
	_ = st.SetUserToolEnabled(ctx, 1, "gmail", "send", false)
	if err := st.CascadeRemoveServer(ctx, "gmail"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.IsUserInstalled(ctx, 1, "gmail"); ok {
		t.Fatal("install not cascaded")
	}
	if d, _ := st.ListUserDisabledTools(ctx, 1, "gmail"); len(d) != 0 {
		t.Fatal("tool prefs not cascaded")
	}
}
