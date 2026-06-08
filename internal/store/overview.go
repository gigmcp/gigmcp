package store

import (
	"context"
	"time"
)

// HeatmapDay is one trailing-window day bucket: Date is the UTC day (YYYY-MM-DD)
// and Count is the number of egress events that day for the user.
type HeatmapDay struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// OverviewStats is the audit-derived dashboard summary for one user.
//
// ToolCalls counts AuditKindEgress events. There is no per-tool-call audit
// event in P1 (only egress/auth/admin), so egress — one row per outbound
// resolution the proxy made on the user's behalf — is the closest available
// signal. MostUsedApp is the server with the most egress events ("" if none).
type OverviewStats struct {
	ToolCalls   int64        `json:"tool_calls"`
	MostUsedApp string       `json:"most_used_app"`
	Heatmap     []HeatmapDay `json:"heatmap"`
}

// AuditStats aggregates a user's egress events over the trailing `days` window
// ending on `now` (inclusive). The window is [now-days+1 .. now] in UTC day
// granularity, so Heatmap always has exactly `days` buckets oldest-first.
// userID must be the effective user's id (per-user; never 0/all here).
func (s *sqliteStore) AuditStats(ctx context.Context, userID int64, days int, now time.Time) (OverviewStats, error) {
	if days <= 0 {
		days = 30
	}
	out := OverviewStats{Heatmap: make([]HeatmapDay, days)}
	// Build the day buckets oldest-first and an index by date string.
	today := now.UTC().Truncate(24 * time.Hour)
	idx := make(map[string]int, days)
	for i := 0; i < days; i++ {
		d := today.AddDate(0, 0, -(days - 1 - i))
		key := d.Format("2006-01-02")
		out.Heatmap[i] = HeatmapDay{Date: key, Count: 0}
		idx[key] = i
	}
	windowStart := today.AddDate(0, 0, -(days - 1)).Unix()

	// Total tool calls = all egress events for the user (not window-limited; the
	// stat is an all-time count, matching the spec's "Tool calls" tile).
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit WHERE user_id=? AND kind='egress'`, userID).
		Scan(&out.ToolCalls); err != nil {
		return OverviewStats{}, err
	}

	// Most-used app: server with the most egress events (all-time).
	row := s.db.QueryRowContext(ctx,
		`SELECT server FROM audit WHERE user_id=? AND kind='egress' AND server<>''
		 GROUP BY server ORDER BY COUNT(*) DESC, server ASC LIMIT 1`, userID)
	_ = row.Scan(&out.MostUsedApp) // no rows → "" (left as zero value)

	// Per-day heatmap buckets within the window.
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, COUNT(*) FROM audit
		 WHERE user_id=? AND kind='egress' AND ts>=?
		 GROUP BY ts`, userID, windowStart)
	if err != nil {
		return OverviewStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var ts, n int64
		if err := rows.Scan(&ts, &n); err != nil {
			return OverviewStats{}, err
		}
		key := time.Unix(ts, 0).UTC().Format("2006-01-02")
		if i, ok := idx[key]; ok {
			out.Heatmap[i].Count += n
		}
	}
	return out, rows.Err()
}
