package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store handles SQLite storage for audit logs
type Store struct {
	db *sql.DB
}

// NewStore creates a new SQLite audit store
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.init(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

// init creates the audit table if it doesn't exist
func (s *Store) init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		user TEXT NOT NULL,
		method TEXT NOT NULL,
		uri TEXT NOT NULL,
		image TEXT,
		command TEXT,
		risk_score INTEGER NOT NULL,
		decision TEXT NOT NULL,
		reason TEXT,
		duration_ms INTEGER NOT NULL,
		policy TEXT,
		violations TEXT
	);
	
	CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_user ON audit_log(user);
	CREATE INDEX IF NOT EXISTS idx_decision ON audit_log(decision);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// Insert adds a new audit entry to the database
func (s *Store) Insert(entry *Entry) error {
	violations := ""
	if len(entry.Violations) > 0 {
		data, _ := json.Marshal(entry.Violations)
		violations = string(data)
	}

	_, err := s.db.Exec(`
		INSERT INTO audit_log (timestamp, user, method, uri, image, command, risk_score, decision, reason, duration_ms, policy, violations)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		entry.Timestamp,
		entry.User,
		entry.Method,
		entry.URI,
		entry.Image,
		entry.Command,
		entry.RiskScore,
		string(entry.Decision),
		entry.Reason,
		entry.DurationMs,
		entry.Policy,
		violations,
	)

	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return nil
}

// Query retrieves audit entries based on filter options
func (s *Store) Query(opts QueryOptions) ([]Entry, error) {
	var conditions []string
	var args []interface{}

	if !opts.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, opts.Since)
	}
	if !opts.Until.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, opts.Until)
	}
	if opts.User != "" {
		conditions = append(conditions, "user = ?")
		args = append(args, opts.User)
	}
	if opts.Decision != "" {
		conditions = append(conditions, "decision = ?")
		args = append(args, string(opts.Decision))
	}

	query := "SELECT id, timestamp, user, method, uri, image, command, risk_score, decision, reason, duration_ms, policy, violations FROM audit_log"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit log: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var entry Entry
		var decisionStr string
		var violations sql.NullString
		var image, command, reason, policy sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.Timestamp,
			&entry.User,
			&entry.Method,
			&entry.URI,
			&image,
			&command,
			&entry.RiskScore,
			&decisionStr,
			&reason,
			&entry.DurationMs,
			&policy,
			&violations,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		entry.Decision = Decision(decisionStr)
		entry.Image = image.String
		entry.Command = command.String
		entry.Reason = reason.String
		entry.Policy = policy.String

		if violations.Valid && violations.String != "" {
			json.Unmarshal([]byte(violations.String), &entry.Violations)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// GetStats returns summary statistics for audit logs
func (s *Store) GetStats(since time.Time) (*Stats, error) {
	stats := &Stats{
		StartTime: since,
		EndTime:   time.Now(),
	}

	// Get counts by decision
	query := `
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN decision = 'allowed' THEN 1 ELSE 0 END) as allowed,
			SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) as denied,
			SUM(CASE WHEN decision = 'warned' THEN 1 ELSE 0 END) as warned,
			AVG(risk_score) as avg_risk,
			AVG(duration_ms) as avg_duration,
			COUNT(DISTINCT user) as unique_users
		FROM audit_log
		WHERE timestamp >= ?
	`

	var avgRisk, avgDuration sql.NullFloat64
	err := s.db.QueryRow(query, since).Scan(
		&stats.TotalRequests,
		&stats.Allowed,
		&stats.Denied,
		&stats.Warned,
		&avgRisk,
		&avgDuration,
		&stats.UniqueUsers,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	stats.AvgRiskScore = avgRisk.Float64
	stats.AvgDurationMs = avgDuration.Float64

	// Get top users
	userQuery := `
		SELECT user, COUNT(*) as requests, SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) as denied
		FROM audit_log
		WHERE timestamp >= ?
		GROUP BY user
		ORDER BY requests DESC
		LIMIT 5
	`
	rows, err := s.db.Query(userQuery, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user UserStat
		if err := rows.Scan(&user.Name, &user.Requests, &user.Denied); err != nil {
			return nil, err
		}
		stats.TopUsers = append(stats.TopUsers, user)
	}

	// Get top denial reasons
	denialQuery := `
		SELECT reason, COUNT(*) as count
		FROM audit_log
		WHERE timestamp >= ? AND decision = 'denied' AND reason != ''
		GROUP BY reason
		ORDER BY count DESC
		LIMIT 5
	`
	rows2, err := s.db.Query(denialQuery, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top denials: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var reason ReasonStat
		if err := rows2.Scan(&reason.Reason, &reason.Count); err != nil {
			return nil, err
		}
		stats.TopDenials = append(stats.TopDenials, reason)
	}

	return stats, nil
}

// DeleteBefore removes entries older than the specified time
func (s *Store) DeleteBefore(before time.Time) (int64, error) {
	result, err := s.db.Exec("DELETE FROM audit_log WHERE timestamp < ?", before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old entries: %w", err)
	}

	return result.RowsAffected()
}

// Count returns the total number of entries
func (s *Store) Count() (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count)
	return count, err
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

