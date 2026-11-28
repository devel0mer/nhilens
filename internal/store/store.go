package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
	_ "modernc.org/sqlite" // Pure-Go SQLite driver (no CGO).
)

// ErrNotFound is returned when no matching scan exists in the database.
var ErrNotFound = errors.New("scan not found")

// ScanSummary contains lightweight metadata for listing stored scans.
type ScanSummary struct {
	ID            string
	AccountID     string
	Region        string
	StartedAt     time.Time
	CompletedAt   time.Time
	IdentityCount int
	FindingCount  int
}

// Store persists and retrieves normalized scan runs in a SQLite database.
type Store struct {
	db *sql.DB
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS scans (
	id                     TEXT PRIMARY KEY,
	account_id             TEXT NOT NULL,
	caller_arn             TEXT NOT NULL,
	region                 TEXT NOT NULL,
	profile                TEXT NOT NULL,
	started_at             TEXT NOT NULL,
	completed_at           TEXT NOT NULL,
	since_window           TEXT NOT NULL,
	cloudtrail_status      TEXT NOT NULL,
	cloudtrail_event_count INTEGER NOT NULL,
	warnings_json          TEXT NOT NULL,
	coverage_json          TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS identities (
	scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	id               TEXT NOT NULL,
	arn              TEXT NOT NULL,
	type             TEXT NOT NULL,
	name             TEXT NOT NULL,
	account          TEXT NOT NULL,
	owner            TEXT,
	agent_likelihood TEXT NOT NULL,
	risk_score       REAL NOT NULL,
	created_at       TEXT,
	last_used_at     TEXT,
	payload_json     TEXT NOT NULL,
	PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS findings (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	identity_id   TEXT NOT NULL,
	rule_id       TEXT NOT NULL,
	rule_name     TEXT NOT NULL,
	severity      TEXT NOT NULL,
	title         TEXT NOT NULL,
	explanation   TEXT NOT NULL,
	remediation   TEXT NOT NULL,
	evidence_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identities_scan_score
	ON identities (scan_id, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_findings_scan_rule
	ON findings (scan_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan_severity
	ON findings (scan_id, severity);
`

// Open opens (or creates) a SQLite database at path and ensures the schema is initialized.
// Pass ":memory:" for an ephemeral in-memory database (useful in tests).
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path cannot be empty")
	}

	isMemory := path == ":memory:" || strings.HasPrefix(path, "file::memory:")
	if !isMemory {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create database directory %q: %w", dir, err)
			}
		}
		// Pre-create the SQLite database file with restrictive 0600 permissions so sensitive
		// AWS account IDs, ARNs, policy documents, and CloudTrail IPs are never world-readable.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create database file %q: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("close pre-created database file %q: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("chmod database file %q: %w", path, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	// SQLite handles concurrent writers best through a single pooled connection.
	db.SetMaxOpenConns(1)

	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
	}
	if !isMemory {
		pragmas = append(pragmas, "PRAGMA journal_mode = WAL;")
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply pragma %q: %w", p, err)
		}
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}
	if err := ensureColumn(db, "scans", "coverage_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate scans.coverage_json: %w", err)
	}

	if !isMemory {
		// Ensure WAL/SHM sidecar files created by SQLite are also owner-only (0600).
		for _, sidecar := range []string{path, path + "-wal", path + "-shm"} {
			if _, statErr := os.Stat(sidecar); statErr == nil {
				_ = os.Chmod(sidecar, 0o600)
			}
		}
	}

	return &Store{db: db}, nil
}

// Close closes the underlying SQLite database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveScan stores a complete ScanRun (metadata, identities, and findings) atomically.
// If a scan with the same ID already exists, it is replaced.
func (s *Store) SaveScan(ctx context.Context, run *model.ScanRun) error {
	if run == nil {
		return errors.New("scan run is nil")
	}
	if strings.TrimSpace(run.ID) == "" {
		return errors.New("scan run ID cannot be empty")
	}

	warningsJSON, err := json.Marshal(nonNilSlice(run.Warnings))
	if err != nil {
		return fmt.Errorf("marshal warnings: %w", err)
	}
	coverageJSON := "{}"
	if run.Coverage != nil {
		rawCov, err := json.Marshal(run.Coverage)
		if err != nil {
			return fmt.Errorf("marshal coverage: %w", err)
		}
		coverageJSON = string(rawCov)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Replace cleanly if re-saving the same scan ID (ON DELETE CASCADE cleans children).
	if _, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE id = ?`, run.ID); err != nil {
		return fmt.Errorf("delete existing scan %q: %w", run.ID, err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO scans (
			id, account_id, caller_arn, region, profile,
			started_at, completed_at, since_window,
			cloudtrail_status, cloudtrail_event_count, warnings_json, coverage_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID,
		run.AccountID,
		run.CallerARN,
		run.Region,
		run.Profile,
		run.StartedAt.UTC().Format(time.RFC3339Nano),
		run.CompletedAt.UTC().Format(time.RFC3339Nano),
		run.SinceWindow,
		run.CloudTrailStatus,
		run.CloudTrailEventCount,
		string(warningsJSON),
		coverageJSON,
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	idStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO identities (
			scan_id, id, arn, type, name, account, owner,
			agent_likelihood, risk_score, created_at, last_used_at, payload_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare identity insert: %w", err)
	}
	defer func() { _ = idStmt.Close() }()

	findingStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings (
			scan_id, identity_id, rule_id, rule_name, severity,
			title, explanation, remediation, evidence_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare finding insert: %w", err)
	}
	defer func() { _ = findingStmt.Close() }()

	for _, ident := range run.Identities {
		payload, err := json.Marshal(ident)
		if err != nil {
			return fmt.Errorf("marshal identity %q: %w", ident.ID, err)
		}

		var owner sql.NullString
		if ident.Owner != nil {
			owner = sql.NullString{String: *ident.Owner, Valid: true}
		}

		if _, err := idStmt.ExecContext(ctx,
			run.ID,
			ident.ID,
			ident.ARN,
			string(ident.Type),
			ident.Name,
			ident.Account,
			owner,
			string(ident.AgentLikelihood),
			ident.RiskScore,
			nullableTime(ident.Created),
			nullableTime(ident.LastUsed),
			string(payload),
		); err != nil {
			return fmt.Errorf("insert identity %q: %w", ident.ID, err)
		}

		for _, f := range ident.Findings {
			evJSON, err := json.Marshal(nonNilSlice(f.Evidence))
			if err != nil {
				return fmt.Errorf("marshal finding evidence for %q/%s: %w", ident.ID, f.RuleID, err)
			}
			if _, err := findingStmt.ExecContext(ctx,
				run.ID,
				ident.ID,
				f.RuleID,
				f.RuleName,
				string(f.Severity),
				f.Title,
				f.Explanation,
				f.Remediation,
				string(evJSON),
			); err != nil {
				return fmt.Errorf("insert finding %s for %q: %w", f.RuleID, ident.ID, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan: %w", err)
	}
	return nil
}

// LoadLatestScan loads the most recently started ScanRun stored in the database.
func (s *Store) LoadLatestScan(ctx context.Context) (*model.ScanRun, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM scans ORDER BY started_at DESC, rowid DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query latest scan: %w", err)
	}
	return s.LoadScan(ctx, id)
}

// LoadScan loads a specific ScanRun by ID including all normalized identities.
func (s *Store) LoadScan(ctx context.Context, scanID string) (*model.ScanRun, error) {
	var (
		run          model.ScanRun
		startedStr   string
		completedStr string
		warningsJSON string
		coverageJSON string
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT id, account_id, caller_arn, region, profile,
		       started_at, completed_at, since_window,
		       cloudtrail_status, cloudtrail_event_count, warnings_json, coverage_json
		FROM scans
		WHERE id = ?`, scanID,
	).Scan(
		&run.ID,
		&run.AccountID,
		&run.CallerARN,
		&run.Region,
		&run.Profile,
		&startedStr,
		&completedStr,
		&run.SinceWindow,
		&run.CloudTrailStatus,
		&run.CloudTrailEventCount,
		&warningsJSON,
		&coverageJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query scan %q: %w", scanID, err)
	}

	if run.StartedAt, err = time.Parse(time.RFC3339Nano, startedStr); err != nil {
		return nil, fmt.Errorf("parse started_at %q: %w", startedStr, err)
	}
	if run.CompletedAt, err = time.Parse(time.RFC3339Nano, completedStr); err != nil {
		return nil, fmt.Errorf("parse completed_at %q: %w", completedStr, err)
	}
	if err := json.Unmarshal([]byte(warningsJSON), &run.Warnings); err != nil {
		return nil, fmt.Errorf("unmarshal warnings: %w", err)
	}
	if len(run.Warnings) == 0 {
		run.Warnings = nil
	}
	if trimmedCov := strings.TrimSpace(coverageJSON); trimmedCov != "" && trimmedCov != "{}" && trimmedCov != "null" {
		var cov model.ScanCoverage
		if err := json.Unmarshal([]byte(trimmedCov), &cov); err != nil {
			return nil, fmt.Errorf("unmarshal coverage: %w", err)
		}
		run.Coverage = &cov
		if len(cov.RegionsScanned) > 0 {
			run.Regions = append([]string(nil), cov.RegionsScanned...)
		}
		if cov.OrganizationID != "" {
			run.OrganizationID = cov.OrganizationID
		}
		if len(cov.AccountSummaries) > 0 {
			run.Accounts = append([]model.AccountScanSummary(nil), cov.AccountSummaries...)
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT payload_json
		FROM identities
		WHERE scan_id = ?
		ORDER BY risk_score DESC, type ASC, name ASC, id ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query identities for scan %q: %w", scanID, err)
	}
	defer func() { _ = rows.Close() }()

	run.Identities = make([]model.Identity, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan identity row: %w", err)
		}
		var ident model.Identity
		if err := json.Unmarshal([]byte(payload), &ident); err != nil {
			return nil, fmt.Errorf("unmarshal identity payload: %w", err)
		}
		run.Identities = append(run.Identities, ident)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identities: %w", err)
	}

	return &run, nil
}

// ListScans returns summaries of all stored scans ordered newest first.
func (s *Store) ListScans(ctx context.Context) ([]ScanSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.account_id, s.region, s.started_at, s.completed_at,
		       (SELECT COUNT(*) FROM identities i WHERE i.scan_id = s.id) AS identity_count,
		       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
		FROM scans s
		ORDER BY s.started_at DESC, s.rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]ScanSummary, 0)
	for rows.Next() {
		var (
			sum          ScanSummary
			startedStr   string
			completedStr string
		)
		if err := rows.Scan(
			&sum.ID,
			&sum.AccountID,
			&sum.Region,
			&startedStr,
			&completedStr,
			&sum.IdentityCount,
			&sum.FindingCount,
		); err != nil {
			return nil, fmt.Errorf("scan summary row: %w", err)
		}
		if sum.StartedAt, err = time.Parse(time.RFC3339Nano, startedStr); err != nil {
			return nil, fmt.Errorf("parse started_at: %w", err)
		}
		if sum.CompletedAt, err = time.Parse(time.RFC3339Nano, completedStr); err != nil {
			return nil, fmt.Errorf("parse completed_at: %w", err)
		}
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan summaries: %w", err)
	}
	return out, nil
}

func nullableTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339Nano), Valid: true}
}

func nonNilSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func ensureColumn(db *sql.DB, table, col, colDef string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, col) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col, colDef))
	return err
}
