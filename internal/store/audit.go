package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Kind constants for AuditEvent.Kind. Use these instead of raw strings so the
// compiler catches typos and callers don't need to import the schema comment.
const (
	AuditKindEgress = "egress"
	AuditKindAuth   = "auth"
	AuditKindAdmin  = "admin"
)

// AuditEvent is one persisted audit row. Kind partitions the
// stream: AuditKindEgress (proxy resolutions, written by the AuditingResolver),
// AuditKindAuth (login/logout) and AuditKindAdmin (profile/credential/
// impersonation/install mutations, written synchronously by API handlers).
type AuditEvent struct {
	ID        int64
	TS        time.Time
	Kind      string // AuditKindEgress | AuditKindAuth | AuditKindAdmin
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
);
CREATE INDEX IF NOT EXISTS audit_user_id ON audit(user_id, id);`

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
// next page. userID filters to one user's events (0 = all events — admin
// paths only). limit is clamped to [1,500]; ≤0 defaults to 100, >500 clamps
// to 500.
//
// WARNING: callers must pass a validated userID; 0 returns ALL events across
// all users and should only be used by admin paths.
//
// NOTE: rows where user_id IS NULL are invisible under any non-zero userID
// filter (the WHERE user_id=? predicate never matches NULL). The API layer
// must be aware that NULL-user rows only appear in the admin (userID==0) view.
func (s *sqliteStore) ListAudit(ctx context.Context, beforeID int64, limit int, userID int64) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	q := `SELECT id,ts,kind,user_id,profile_id,server,host,decision,detail FROM audit`
	var conds []string
	var args []any
	if beforeID > 0 {
		conds = append(conds, "id < ?")
		args = append(args, beforeID)
	}
	if userID != 0 {
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
		e.TS = time.Unix(ts, 0).UTC()
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
