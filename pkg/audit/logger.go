package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger provides dual-output audit logging (JSON Lines + SQLite)
type Logger struct {
	store     *Store
	jsonFile  *os.File
	jsonPath  string
	mu        sync.Mutex
	enabled   bool
}

// NewLogger creates a new audit logger
func NewLogger(auditDir string) (*Logger, error) {
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	// Open SQLite store
	dbPath := filepath.Join(auditDir, "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit store: %w", err)
	}

	// Open JSON Lines file for append
	jsonPath := filepath.Join(auditDir, "audit.jsonl")
	jsonFile, err := os.OpenFile(jsonPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("failed to open JSON log: %w", err)
	}

	return &Logger{
		store:    store,
		jsonFile: jsonFile,
		jsonPath: jsonPath,
		enabled:  true,
	}, nil
}

// Log writes an audit entry to both outputs
func (l *Logger) Log(entry *Entry) error {
	if !l.enabled {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write to SQLite
	if err := l.store.Insert(entry); err != nil {
		return fmt.Errorf("failed to write to SQLite: %w", err)
	}

	// Write to JSON Lines
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	if _, err := l.jsonFile.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write to JSON log: %w", err)
	}

	return nil
}

// Query retrieves entries from the SQLite store
func (l *Logger) Query(opts QueryOptions) ([]Entry, error) {
	return l.store.Query(opts)
}

// GetStats returns summary statistics
func (l *Logger) GetStats(since time.Time) (*Stats, error) {
	return l.store.GetStats(since)
}

// DeleteBefore removes old entries from the SQLite store
func (l *Logger) DeleteBefore(before time.Time) (int64, error) {
	return l.store.DeleteBefore(before)
}

// Count returns the total number of entries
func (l *Logger) Count() (int64, error) {
	return l.store.Count()
}

// TailJSON opens the JSON log for reading (for tail -f style watching)
func (l *Logger) TailJSON(lines int) ([]Entry, error) {
	file, err := os.Open(l.jsonPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	// Read all lines first, then return last N
	var allEntries []Entry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // Skip malformed lines
		}
		allEntries = append(allEntries, entry)
	}

	if lines <= 0 || lines >= len(allEntries) {
		return allEntries, nil
	}

	return allEntries[len(allEntries)-lines:], nil
}

// WatchJSON returns a channel that emits new entries as they are written
func (l *Logger) WatchJSON() (<-chan Entry, func(), error) {
	file, err := os.Open(l.jsonPath)
	if err != nil {
		return nil, nil, err
	}

	// Seek to end
	file.Seek(0, io.SeekEnd)

	ch := make(chan Entry, 100)
	done := make(chan struct{})

	go func() {
		defer file.Close()
		defer close(ch)

		reader := bufio.NewReader(file)
		for {
			select {
			case <-done:
				return
			default:
				line, err := reader.ReadBytes('\n')
				if err != nil {
					if err == io.EOF {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					return
				}

				var entry Entry
				if err := json.Unmarshal(line, &entry); err != nil {
					continue
				}

				select {
				case ch <- entry:
				case <-done:
					return
				}
			}
		}
	}()

	cancel := func() {
		close(done)
	}

	return ch, cancel, nil
}

// Close closes all resources
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []error

	if l.jsonFile != nil {
		if err := l.jsonFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if l.store != nil {
		if err := l.store.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing logger: %v", errs)
	}

	return nil
}

// OpenStore opens a read-only connection to the audit database
// Used by CLI commands that don't need the full logger
func OpenStore(auditDir string) (*Store, error) {
	dbPath := filepath.Join(auditDir, "audit.db")
	return NewStore(dbPath)
}

