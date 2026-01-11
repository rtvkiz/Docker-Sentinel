package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store handles SQLite storage for audit entries
type Store struct {
	db     *sql.DB
	dbPath string
}

// NewStore creates a new SQLite audit store
func NewStore(auditDir string) (*Store, error) {
	// Ensure audit directory exists with secure permissions
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	dbPath := filepath.Join(auditDir, "audit.db")

	// Check if database file exists
	dbExists := false
	if _, err := os.Stat(dbPath); err == nil {
		dbExists = true
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open audit database: %w", err)
	}

	// Set secure permissions on new database file
	if !dbExists {
		if err := os.Chmod(dbPath, 0600); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set database permissions: %w", err)
		}
	}

	store := &Store{
		db:     db,
		dbPath: dbPath,
	}

	// Initialize schema
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

// initSchema creates the audit table if it doesn't exist
func (s *Store) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		user TEXT NOT NULL DEFAULT '',
		method TEXT NOT NULL,
		uri TEXT NOT NULL,
		image TEXT DEFAULT '',
		command TEXT DEFAULT '',
		risk_score INTEGER DEFAULT 0,
		decision TEXT NOT NULL,
		reason TEXT DEFAULT '',
		duration_ms INTEGER DEFAULT 0,
		policy TEXT DEFAULT '',
		violations TEXT DEFAULT '[]'
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_entries(timestamp);
	CREATE INDEX IF NOT EXISTS idx_user ON audit_entries(user);
	CREATE INDEX IF NOT EXISTS idx_decision ON audit_entries(decision);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Insert inserts a new audit entry
func (s *Store) Insert(entry *Entry) error {
	violations, _ := json.Marshal(entry.Violations)

	_, err := s.db.Exec(`
		INSERT INTO audit_entries (timestamp, user, method, uri, image, command, risk_score, decision, reason, duration_ms, policy, violations)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		entry.Timestamp,
		entry.User,
		entry.Method,
		entry.URI,
		entry.Image,
		entry.Command,
		entry.RiskScore,
		entry.Decision,
		entry.Reason,
		entry.DurationMs,
		entry.Policy,
		string(violations),
	)
	return err
}

// Query retrieves audit entries based on options
func (s *Store) Query(opts QueryOptions) ([]*Entry, error) {
	var conditions []string
	var args []interface{}

	if opts.Since != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *opts.Since)
	}

	if opts.Until != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *opts.Until)
	}

	if opts.User != "" {
		conditions = append(conditions, "user = ?")
		args = append(args, opts.User)
	}

	if opts.Decision != "" {
		conditions = append(conditions, "decision = ?")
		args = append(args, opts.Decision)
	}

	query := "SELECT id, timestamp, user, method, uri, image, command, risk_score, decision, reason, duration_ms, policy, violations FROM audit_entries"

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	if opts.OrderDesc {
		query += " ORDER BY timestamp DESC"
	} else {
		query += " ORDER BY timestamp ASC"
	}

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}

	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries: %w", err)
	}
	defer rows.Close()

	var entries []*Entry
	for rows.Next() {
		entry := &Entry{}
		var violations string
		var timestamp string

		err := rows.Scan(
			&entry.ID,
			&timestamp,
			&entry.User,
			&entry.Method,
			&entry.URI,
			&entry.Image,
			&entry.Command,
			&entry.RiskScore,
			&entry.Decision,
			&entry.Reason,
			&entry.DurationMs,
			&entry.Policy,
			&violations,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		// Parse timestamp
		entry.Timestamp, _ = time.Parse("2006-01-02 15:04:05.999999999-07:00", timestamp)
		if entry.Timestamp.IsZero() {
			entry.Timestamp, _ = time.Parse("2006-01-02T15:04:05Z", timestamp)
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp, _ = time.Parse(time.RFC3339, timestamp)
		}

		// Parse violations (ignore error - violations field is optional)
		if violations != "" && violations != "[]" {
			_ = json.Unmarshal([]byte(violations), &entry.Violations)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// GetStats retrieves aggregated statistics
func (s *Store) GetStats(since, until *time.Time) (*Stats, error) {
	stats := &Stats{}

	var conditions []string
	var args []interface{}

	if since != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *since)
		stats.Since = *since
	}

	if until != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *until)
		stats.Until = *until
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total counts
	row := s.db.QueryRow(`
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN decision = 'allowed' THEN 1 ELSE 0 END) as allowed,
			SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) as denied,
			SUM(CASE WHEN decision = 'warned' THEN 1 ELSE 0 END) as warned,
			COUNT(DISTINCT user) as unique_users,
			COALESCE(AVG(risk_score), 0) as avg_risk,
			COALESCE(AVG(duration_ms), 0) as avg_duration
		FROM audit_entries`+whereClause, args...)

	err := row.Scan(
		&stats.TotalRequests,
		&stats.AllowedCount,
		&stats.DeniedCount,
		&stats.WarnedCount,
		&stats.UniqueUsers,
		&stats.AvgRiskScore,
		&stats.AvgDurationMs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// Get top users
	rows, err := s.db.Query(`
		SELECT user, COUNT(*) as count,
			SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) as denied,
			SUM(CASE WHEN decision = 'allowed' THEN 1 ELSE 0 END) as allowed
		FROM audit_entries`+whereClause+`
		GROUP BY user
		ORDER BY count DESC
		LIMIT 10`, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var us UserStat
			if err := rows.Scan(&us.User, &us.Count, &us.Denied, &us.Allowed); err != nil {
				continue // Skip malformed rows
			}
			stats.TopUsers = append(stats.TopUsers, us)
		}
	}

	// Get top denial reasons
	rows, err = s.db.Query(`
		SELECT reason, COUNT(*) as count
		FROM audit_entries
		WHERE decision = 'denied'`+strings.Replace(whereClause, "WHERE", " AND ", 1)+`
		GROUP BY reason
		ORDER BY count DESC
		LIMIT 10`, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rs ReasonStat
			if err := rows.Scan(&rs.Reason, &rs.Count); err != nil {
				continue // Skip malformed rows
			}
			if rs.Reason != "" {
				stats.TopDeniedReasons = append(stats.TopDeniedReasons, rs)
			}
		}
	}

	return stats, nil
}

// DeleteBefore deletes entries before the given time
func (s *Store) DeleteBefore(before time.Time) (int64, error) {
	result, err := s.db.Exec("DELETE FROM audit_entries WHERE timestamp < ?", before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete entries: %w", err)
	}
	return result.RowsAffected()
}

// Count returns the total number of entries
func (s *Store) Count() (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM audit_entries").Scan(&count)
	return count, err
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// Path returns the database file path
func (s *Store) Path() string {
	return s.dbPath
}

