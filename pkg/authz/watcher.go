package authz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatcherConfig holds configuration for the policy watcher
type WatcherConfig struct {
	// PoliciesDir is the directory to watch
	PoliciesDir string

	// DebounceDuration is the time to wait after last event before triggering reload
	DebounceDuration time.Duration

	// FilePatterns specifies which files to watch (e.g., "*.yaml", "*.yml")
	FilePatterns []string
}

// DefaultWatcherConfig returns sensible defaults for the watcher
func DefaultWatcherConfig(policiesDir string, debounce time.Duration) *WatcherConfig {
	return &WatcherConfig{
		PoliciesDir:      policiesDir,
		DebounceDuration: debounce,
		FilePatterns:     []string{"*.yaml", "*.yml"},
	}
}

// PolicyWatcher watches the policies directory for changes and triggers reloads
type PolicyWatcher struct {
	config  *WatcherConfig
	watcher *fsnotify.Watcher

	// reloadFn is the callback to trigger policy reload
	reloadFn func() error

	// logFn is the logging function
	logFn func(level, format string, args ...interface{})

	// Debouncing
	debounceTimer *time.Timer
	debounceMu    sync.Mutex

	// Lifecycle
	ctx     context.Context
	cancel  context.CancelFunc
	doneCh  chan struct{}
	mu      sync.Mutex
	running bool
}

// NewPolicyWatcher creates a new policy watcher
func NewPolicyWatcher(config *WatcherConfig, reloadFn func() error, logFn func(level, format string, args ...interface{})) (*PolicyWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &PolicyWatcher{
		config:   config,
		watcher:  watcher,
		reloadFn: reloadFn,
		logFn:    logFn,
		ctx:      ctx,
		cancel:   cancel,
		doneCh:   make(chan struct{}),
	}, nil
}

// Start begins watching for file changes
func (pw *PolicyWatcher) Start() error {
	pw.mu.Lock()
	if pw.running {
		pw.mu.Unlock()
		return fmt.Errorf("watcher already running")
	}
	pw.running = true
	pw.mu.Unlock()

	// Ensure directory exists
	if _, err := os.Stat(pw.config.PoliciesDir); os.IsNotExist(err) {
		pw.logFn("warn", "Policies directory does not exist: %s (creating)", pw.config.PoliciesDir)
		if err := os.MkdirAll(pw.config.PoliciesDir, 0755); err != nil {
			return fmt.Errorf("failed to create policies directory: %w", err)
		}
	}

	// Add directory to watcher
	if err := pw.watcher.Add(pw.config.PoliciesDir); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", pw.config.PoliciesDir, err)
	}

	// Start event handling goroutine
	go pw.handleEvents()

	pw.logFn("info", "Policy watcher started (watching: %s, debounce: %v)", pw.config.PoliciesDir, pw.config.DebounceDuration)
	return nil
}

// Stop gracefully stops the watcher
func (pw *PolicyWatcher) Stop() error {
	pw.mu.Lock()
	if !pw.running {
		pw.mu.Unlock()
		return nil
	}
	pw.running = false
	pw.mu.Unlock()

	// Cancel context to signal goroutine to exit
	pw.cancel()

	// Close the fsnotify watcher
	if err := pw.watcher.Close(); err != nil {
		pw.logFn("warn", "Error closing file watcher: %v", err)
	}

	// Wait for goroutine to finish with timeout
	select {
	case <-pw.doneCh:
		pw.logFn("debug", "Policy watcher stopped")
	case <-time.After(5 * time.Second):
		pw.logFn("warn", "Timeout waiting for policy watcher to stop")
	}

	// Cancel any pending debounce timer
	pw.debounceMu.Lock()
	if pw.debounceTimer != nil {
		pw.debounceTimer.Stop()
	}
	pw.debounceMu.Unlock()

	return nil
}

// handleEvents processes fsnotify events in a goroutine
func (pw *PolicyWatcher) handleEvents() {
	defer close(pw.doneCh)

	for {
		select {
		case <-pw.ctx.Done():
			return

		case event, ok := <-pw.watcher.Events:
			if !ok {
				return
			}

			// Only process relevant file types
			if !pw.isRelevantFile(event.Name) {
				continue
			}

			// Handle relevant operations
			switch {
			case event.Has(fsnotify.Write):
				pw.logFn("debug", "Policy file modified: %s", filepath.Base(event.Name))
				pw.scheduleReload(event.Name)

			case event.Has(fsnotify.Create):
				pw.logFn("debug", "Policy file created: %s", filepath.Base(event.Name))
				pw.scheduleReload(event.Name)

			case event.Has(fsnotify.Remove):
				pw.logFn("debug", "Policy file removed: %s", filepath.Base(event.Name))
				pw.scheduleReload(event.Name)

			case event.Has(fsnotify.Rename):
				pw.logFn("debug", "Policy file renamed: %s", filepath.Base(event.Name))
				pw.scheduleReload(event.Name)
			}

		case err, ok := <-pw.watcher.Errors:
			if !ok {
				return
			}
			pw.logFn("error", "File watcher error: %v", err)
		}
	}
}

// scheduleReload debounces reload requests
func (pw *PolicyWatcher) scheduleReload(eventPath string) {
	pw.debounceMu.Lock()
	defer pw.debounceMu.Unlock()

	// Cancel any pending reload
	if pw.debounceTimer != nil {
		pw.debounceTimer.Stop()
	}

	// Schedule new reload after debounce period
	pw.debounceTimer = time.AfterFunc(pw.config.DebounceDuration, func() {
		pw.logFn("info", "Policy file changed: %s, triggering hot reload...", filepath.Base(eventPath))

		if err := pw.reloadFn(); err != nil {
			pw.logFn("error", "Hot reload failed: %v", err)
		} else {
			pw.logFn("info", "Hot reload completed successfully")
		}
	})
}

// isRelevantFile checks if the file matches watched patterns
func (pw *PolicyWatcher) isRelevantFile(path string) bool {
	filename := filepath.Base(path)

	for _, pattern := range pw.config.FilePatterns {
		matched, err := filepath.Match(pattern, filename)
		if err == nil && matched {
			return true
		}
	}
	return false
}
