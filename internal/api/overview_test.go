package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestOverviewEndpoint(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	user, cookie := seedUserSession(t, st, "alice@x", "user")

	uid := user.ID
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(context.Background(), store.AuditEvent{
			Kind: store.AuditKindEgress, UserID: &uid, Server: "gmail", TS: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/overview", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var resp struct {
		ToolCalls   int64  `json:"tool_calls"`
		Apps        int64  `json:"apps"`
		Connected   int64  `json:"connected"`
		Profiles    int64  `json:"profiles"`
		MostUsedApp string `json:"most_used_app"`
		Heatmap     []struct {
			Date  string `json:"date"`
			Count int64  `json:"count"`
		} `json:"heatmap"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if resp.ToolCalls != 3 {
		t.Fatalf("tool_calls: want 3, got %d", resp.ToolCalls)
	}
	if resp.MostUsedApp != "gmail" {
		t.Fatalf("most_used_app: want gmail, got %q", resp.MostUsedApp)
	}
	if len(resp.Heatmap) == 0 {
		t.Fatalf("heatmap must not be empty")
	}
}

func TestOverviewRequiresSession(t *testing.T) {
	_, ts, _, _ := newTestAPI(t)
	code, body := doJSON(t, ts, nil, "GET", "/api/overview", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthed overview: want 401, got %d: %s", code, body)
	}
}
