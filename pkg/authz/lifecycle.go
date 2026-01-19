package authz

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// Daemon manages the plugin daemon lifecycle
type Daemon struct {
	plugin  *Plugin
	server  *Server
	config  *PluginConfig
	watcher *PolicyWatcher
	sigCh   chan os.Signal
	doneCh  chan struct{}
}

// NewDaemon creates a new daemon instance
func NewDaemon(config *PluginConfig) (*Daemon, error) {
	// Create plugin
	plugin, err := NewPlugin(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin: %w", err)
	}

	// Create server
	server := NewServer(plugin, config.SocketPath)

	d := &Daemon{
		plugin: plugin,
		server: server,
		config: config,
		sigCh:  make(chan os.Signal, 1),
		doneCh: make(chan struct{}),
	}

	// Create policy watcher if hot reload is enabled
	if config.HotReload && config.PoliciesDir != "" {
		watcherCfg := DefaultWatcherConfig(config.PoliciesDir, config.HotReloadDebounce)
		// Also watch the config directory for active_policy changes
		configDir := "/etc/sentinel"
		if envDir := os.Getenv("SENTINEL_CONFIG_DIR"); envDir != "" {
			configDir = envDir
		}
		watcherCfg.ConfigDir = configDir
		watcher, err := NewPolicyWatcher(watcherCfg, d.Reload, plugin.log)
		if err != nil {
			plugin.log("warn", "Failed to create policy watcher: %v (hot reload disabled)", err)
		} else {
			d.watcher = watcher
		}
	}

	return d, nil
}

// Start starts the daemon
func (d *Daemon) Start(foreground bool) error {
	// Check if already running
	if pid, err := d.readPID(); err == nil && pid > 0 {
		if d.isProcessRunning(pid) {
			return fmt.Errorf("daemon already running with PID %d", pid)
		}
	}

	// Write PID file
	if err := d.writePID(); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Start policy watcher if configured
	if d.watcher != nil {
		if err := d.watcher.Start(); err != nil {
			d.plugin.log("warn", "Failed to start policy watcher: %v (hot reload disabled)", err)
		} else {
			d.plugin.log("info", "Hot reload enabled (watching: %s)", d.config.PoliciesDir)
		}
	}

	// Setup signal handling
	d.setupSignals()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := d.server.Start(); err != nil {
			errCh <- err
		}
		close(d.doneCh)
	}()

	d.plugin.log("info", "Daemon started (PID: %d)", os.Getpid())

	// Give server a moment to start and check for immediate errors
	select {
	case err := <-errCh:
		d.cleanup()
		return err
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	if foreground {
		fmt.Println("Running in foreground. Press Ctrl+C to stop.")
	}

	// Always wait for signal or error - daemon must keep running
	select {
	case err := <-errCh:
		d.cleanup()
		return err
	case <-d.doneCh:
		d.cleanup()
		return nil
	}
}

// Stop stops the daemon gracefully
func (d *Daemon) Stop() error {
	d.plugin.log("info", "Stopping daemon...")

	// Stop policy watcher first
	if d.watcher != nil {
		if err := d.watcher.Stop(); err != nil {
			d.plugin.log("warn", "Error stopping policy watcher: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.config.GracePeriod)
	defer cancel()

	// Stop server
	if err := d.server.Stop(ctx); err != nil {
		return fmt.Errorf("error stopping server: %w", err)
	}

	// Close plugin resources
	if err := d.plugin.Close(); err != nil {
		d.plugin.log("warn", "Error closing plugin: %v", err)
	}

	// Cleanup
	d.cleanup()

	return nil
}

// Reload reloads the configuration
func (d *Daemon) Reload() error {
	d.plugin.log("info", "Reloading configuration...")
	return d.plugin.ReloadPolicy()
}

// Status returns the daemon status
func (d *Daemon) Status() (*DaemonStatus, error) {
	pid, err := d.readPID()
	if err != nil {
		return &DaemonStatus{
			Running: false,
			Message: "Daemon not running",
		}, nil
	}

	if !d.isProcessRunning(pid) {
		return &DaemonStatus{
			Running: false,
			PID:     pid,
			Message: "Daemon not running (stale PID file)",
		}, nil
	}

	// Get health status
	health := d.plugin.HealthCheck()

	return &DaemonStatus{
		Running:      true,
		PID:          pid,
		SocketPath:   d.config.SocketPath,
		PolicyLoaded: health.PolicyLoaded,
		PolicyName:   health.PolicyName,
		Uptime:       health.Uptime,
		Message:      health.Message,
	}, nil
}

// DaemonStatus represents the daemon status
type DaemonStatus struct {
	Running      bool   `json:"running"`
	PID          int    `json:"pid,omitempty"`
	SocketPath   string `json:"socket_path,omitempty"`
	PolicyLoaded bool   `json:"policy_loaded"`
	PolicyName   string `json:"policy_name,omitempty"`
	Uptime       string `json:"uptime,omitempty"`
	Message      string `json:"message"`
}

// setupSignals sets up signal handling
func (d *Daemon) setupSignals() {
	signal.Notify(d.sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range d.sigCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				d.plugin.log("info", "Received %s signal, shutting down...", sig)
				d.Stop()
				os.Exit(0)
			case syscall.SIGHUP:
				d.plugin.log("info", "Received SIGHUP, reloading configuration...")
				if err := d.Reload(); err != nil {
					d.plugin.log("error", "Failed to reload: %v", err)
				}
			}
		}
	}()
}

// writePID writes the PID file
func (d *Daemon) writePID() error {
	pidDir := d.config.PIDFile[:len(d.config.PIDFile)-len("/"+d.config.PIDFile[len(d.config.PIDFile)-1:])]
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		// Ignore error, directory might already exist
	}

	return os.WriteFile(d.config.PIDFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// readPID reads the PID from the PID file
func (d *Daemon) readPID() (int, error) {
	data, err := os.ReadFile(d.config.PIDFile)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(string(data))
}

// isProcessRunning checks if a process with the given PID is running
func (d *Daemon) isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Send signal 0 to check if process exists
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// cleanup removes PID file and socket
func (d *Daemon) cleanup() {
	// Remove PID file
	os.Remove(d.config.PIDFile)
}

// ReloadByPID sends SIGHUP to a running daemon to trigger policy reload
func ReloadByPID(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("daemon not running (no PID file)")
		}
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return fmt.Errorf("invalid PID in file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Check if process is running
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("daemon not running (stale PID file)")
	}

	// Send SIGHUP to trigger reload
	if err := process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to send reload signal: %w", err)
	}

	return nil
}

// StopByPID stops a running daemon by reading its PID file
func StopByPID(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("daemon not running (no PID file)")
		}
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return fmt.Errorf("invalid PID in file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Send SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send signal: %w", err)
	}

	// Wait for process to exit
	for i := 0; i < 30; i++ {
		if err := process.Signal(syscall.Signal(0)); err != nil {
			// Process has exited
			os.Remove(pidFile)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process: %w", err)
	}

	os.Remove(pidFile)
	return nil
}

// GetStatus returns the status of a daemon by checking its PID file and socket
func GetStatus(pidFile, socketPath string) (*DaemonStatus, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &DaemonStatus{
				Running: false,
				Message: "Daemon not running",
			}, nil
		}
		return nil, fmt.Errorf("failed to read PID file: %w", err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return &DaemonStatus{
			Running: false,
			Message: "Invalid PID file",
		}, nil
	}

	// Check if process is running
	process, err := os.FindProcess(pid)
	if err != nil {
		return &DaemonStatus{
			Running: false,
			PID:     pid,
			Message: "Process not found",
		}, nil
	}

	if err := process.Signal(syscall.Signal(0)); err != nil {
		return &DaemonStatus{
			Running: false,
			PID:     pid,
			Message: "Process not running (stale PID file)",
		}, nil
	}

	// Check socket
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return &DaemonStatus{
			Running: true,
			PID:     pid,
			Message: "Running but socket not found",
		}, nil
	}

	return &DaemonStatus{
		Running:    true,
		PID:        pid,
		SocketPath: socketPath,
		Message:    "Daemon is running",
	}, nil
}
