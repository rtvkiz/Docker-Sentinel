package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Logger handles dual logging to JSON Lines file and SQLite database
type Logger struct {
	jsonFile *os.File
	jsonPath string
	store    *Store
	mu       sync.Mutex
	enabled  bool
}

// LoggerConfig contains configuration for the audit logger
type LoggerConfig struct {
	// AuditDir is the directory for audit files
	AuditDir string

	// Enabled controls whether audit logging is active
	Enabled bool
}

// NewLogger creates a new audit logger
func NewLogger(config LoggerConfig) (*Logger, error) {
	if !config.Enabled {
		return &Logger{enabled: false}, nil
	}

	// Ensure audit directory exists with secure permissions (owner + group only)
	if err := os.MkdirAll(config.AuditDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	// Open JSON Lines file for append with secure permissions (owner read/write only)
	jsonPath := filepath.Join(config.AuditDir, "audit.jsonl")
	jsonFile, err := os.OpenFile(jsonPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open JSON audit log: %w", err)
	}

	// Open SQLite store
	store, err := NewStore(config.AuditDir)
	if err != nil {
		jsonFile.Close()
		return nil, fmt.Errorf("failed to open SQLite store: %w", err)
	}

	return &Logger{
		jsonFile: jsonFile,
		jsonPath: jsonPath,
		store:    store,
		enabled:  true,
	}, nil
}

// Log writes an audit entry to both JSON and SQLite
func (l *Logger) Log(entry *Entry) error {
	if !l.enabled {
		return nil
	}

	// Redact secrets before logging to prevent sensitive data leakage
	entry.RedactSecrets()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write to JSON Lines file
	if l.jsonFile != nil {
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal audit entry: %w", err)
		}
		if _, err := l.jsonFile.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write to JSON log: %w", err)
		}
		// Sync to disk for durability
		l.jsonFile.Sync()
	}

	// Write to SQLite
	if l.store != nil {
		if err := l.store.Insert(entry); err != nil {
			return fmt.Errorf("failed to insert into SQLite: %w", err)
		}
	}

	return nil
}

// Query retrieves audit entries from SQLite
func (l *Logger) Query(opts QueryOptions) ([]*Entry, error) {
	if !l.enabled || l.store == nil {
		return nil, nil
	}
	return l.store.Query(opts)
}

// GetStats retrieves statistics from SQLite
func (l *Logger) GetStats(opts QueryOptions) (*Stats, error) {
	if !l.enabled || l.store == nil {
		return nil, nil
	}
	return l.store.GetStats(opts.Since, opts.Until)
}

// DeleteBefore deletes entries before the given time
func (l *Logger) DeleteBefore(opts QueryOptions) (int64, error) {
	if !l.enabled || l.store == nil {
		return 0, nil
	}
	if opts.Until == nil {
		return 0, fmt.Errorf("until time is required for deletion")
	}
	return l.store.DeleteBefore(*opts.Until)
}

// Count returns the total number of entries
func (l *Logger) Count() (int64, error) {
	if !l.enabled || l.store == nil {
		return 0, nil
	}
	return l.store.Count()
}

// JSONPath returns the path to the JSON Lines file
func (l *Logger) JSONPath() string {
	return l.jsonPath
}

// DBPath returns the path to the SQLite database
func (l *Logger) DBPath() string {
	if l.store != nil {
		return l.store.Path()
	}
	return ""
}

// IsEnabled returns whether audit logging is enabled
func (l *Logger) IsEnabled() bool {
	return l.enabled
}

// Close closes the logger and releases resources
func (l *Logger) Close() error {
	if !l.enabled {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []error

	if l.jsonFile != nil {
		if err := l.jsonFile.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close JSON file: %w", err))
		}
	}

	if l.store != nil {
		if err := l.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close SQLite: %w", err))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// GetDefaultAuditDir returns the default audit directory based on config location
func GetDefaultAuditDir(configDir string) string {
	if configDir != "" {
		return filepath.Join(configDir, "audit")
	}

	// Check for system directory
	if os.Geteuid() == 0 {
		return "/etc/sentinel/audit"
	}

	// User home directory fallback
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".sentinel", "audit")
}

