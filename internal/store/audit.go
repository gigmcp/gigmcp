package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// AuditEvent is one persisted audit row (spec §3, §7). Kind partitions the
// stream: "egress" (proxy resolutions, written by the AuditingResolver),
// "auth" (login/logout) and "admin" (profile/credential/impersonation/install
// mutations, written synchronously by API handlers).
type AuditEvent struct {
	ID        int64
	TS        time.Time
	Kind      string // 'egress' | 'auth' | 'admin'
	UserID    *int64
	ProfileID *int64
	Server    string
	Host      string
	Decision  string
	Detail    string
}

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	kind       TEXT NOT NULL CHECK(kind IN ('egress','auth','admin')),
	user_id    INTEGER,
	profile_id INTEGER,
	server     TEXT NOT NULL DEFAULT '',
	host       TEXT NOT NULL DEFAULT '',
	decision   TEXT NOT NULL DEFAULT '',
	detail     TEXT NOT NULL DEFAULT ''
);`

// AppendAudit inserts an audit row. A zero TS means "now".
func (s *sqliteStore) AppendAudit(ctx context.Context, e AuditEvent) error {
	ts := e.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	var uid, pid any // nil → SQL NULL
	if e.UserID != nil {
		uid = *e.UserID
	}
	if e.ProfileID != nil {
		pid = *e.ProfileID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit (ts,kind,user_id,profile_id,server,host,decision,detail)
		 VALUES (?,?,?,?,?,?,?,?)`,
		ts.Unix(), e.Kind, uid, pid, e.Server, e.Host, e.Decision, e.Detail)
	return err
}

// ListAudit returns audit rows newest-first with keyset pagination:
// beforeID == 0 starts at the newest row; pass the last row's ID to get the
// next page. userID filters to one user's events (0 = all). limit is clamped
// to [1,500] (defaults to 100).
func (s *sqliteStore) ListAudit(ctx context.Context, beforeID int64, limit int, userID int64) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id,ts,kind,user_id,profile_id,server,host,decision,detail FROM audit`
	var conds []string
	var args []any
	if beforeID > 0 {
		conds = append(conds, "id < ?")
		args = append(args, beforeID)
	}
	if userID > 0 {
		conds = append(conds, "user_id = ?")
		args = append(args, userID)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var ts int64
		var uid, pid sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &uid, &pid, &e.Server, &e.Host, &e.Decision, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		if uid.Valid {
			v := uid.Int64
			e.UserID = &v
		}
		if pid.Valid {
			v := pid.Int64
			e.ProfileID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
