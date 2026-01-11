package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/audit"
)

// Server handles the Docker authorization plugin HTTP server
type Server struct {
	plugin     *Plugin
	socketPath string
	listener   net.Listener
	httpServer *http.Server
	mu         sync.Mutex
	running    bool
}

// NewServer creates a new plugin server
func NewServer(plugin *Plugin, socketPath string) *Server {
	s := &Server{
		plugin:     plugin,
		socketPath: socketPath,
	}

	mux := http.NewServeMux()

	// Plugin activation endpoint
	mux.HandleFunc("/Plugin.Activate", s.handleActivate)

	// Authorization endpoints
	mux.HandleFunc("/"+AuthZApiRequest, s.handleAuthZReq)
	mux.HandleFunc("/"+AuthZApiResponse, s.handleAuthZRes)

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return s
}

// Start starts the plugin server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.mu.Unlock()

	// Ensure plugin directory exists
	pluginDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory %s: %w", pluginDir, err)
	}

	// Remove existing socket if present
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket at %s: %w", s.socketPath, err)
	}
	s.listener = listener

	// Set socket permissions (readable by docker group)
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	s.plugin.log("info", "Server starting on %s", s.socketPath)

	// Serve HTTP on the Unix socket
	if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	s.plugin.log("info", "Server shutting down...")

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("error during shutdown: %w", err)
	}

	// Remove socket file
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		s.plugin.log("warn", "Failed to remove socket file: %v", err)
	}

	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	s.plugin.log("info", "Server stopped")
	return nil
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// handleActivate responds to plugin activation requests
func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	s.plugin.log("debug", "Plugin activation requested")

	response := PluginActivation{
		Implements: []string{AuthZApiImplements},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.plugin.log("error", "Failed to encode activation response: %v", err)
	}
}

// handleAuthZReq handles pre-request authorization
func (s *Server) handleAuthZReq(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.respondError(w, "failed to read request body", err)
		return
	}

	// Parse authorization request
	var req AuthZRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.respondError(w, "failed to parse authorization request", err)
		return
	}

	// Log the request
	s.plugin.log("debug", "AuthZReq: user=%s method=%s uri=%s", req.User, req.RequestMethod, req.RequestURI)

	// Delegate to plugin for authorization decision with audit info
	result := s.plugin.AuthZReqWithAudit(&req)
	response := result.Response

	// Calculate duration
	duration := time.Since(startTime)

	// Log the decision
	if response.Allow {
		s.plugin.log("debug", "AuthZReq allowed in %v: %s %s", duration, req.RequestMethod, req.RequestURI)
	} else {
		s.plugin.log("info", "AuthZReq denied in %v: %s %s - %s", duration, req.RequestMethod, req.RequestURI, response.Msg)
	}

	// Create audit entry
	decision := audit.DecisionAllowed
	reason := ""
	if !response.Allow {
		decision = audit.DecisionDenied
		reason = response.Msg
	} else if len(result.Violations) > 0 {
		decision = audit.DecisionWarned
		reason = response.Msg
	}

	auditEntry := &audit.Entry{
		Timestamp:  startTime,
		User:       req.User,
		Method:     req.RequestMethod,
		URI:        req.RequestURI,
		Image:      result.Image,
		Command:    result.Command,
		RiskScore:  result.RiskScore,
		Decision:   decision,
		Reason:     reason,
		DurationMs: duration.Milliseconds(),
		Policy:     result.PolicyName,
		Violations: result.Violations,
	}

	// Log audit entry
	s.plugin.LogAuditEntry(auditEntry)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.plugin.log("error", "Failed to encode authorization response: %v", err)
	}
}

// handleAuthZRes handles post-request authorization
func (s *Server) handleAuthZRes(w http.ResponseWriter, r *http.Request) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.respondError(w, "failed to read request body", err)
		return
	}

	// Parse authorization request
	var req AuthZRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.respondError(w, "failed to parse authorization request", err)
		return
	}

	// Delegate to plugin for authorization decision
	response := s.plugin.AuthZRes(&req)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.plugin.log("error", "Failed to encode authorization response: %v", err)
	}
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.plugin.HealthCheck()

	w.Header().Set("Content-Type", "application/json")
	if health.Healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(health)
}

// respondError sends an error response
func (s *Server) respondError(w http.ResponseWriter, message string, err error) {
	s.plugin.log("error", "%s: %v", message, err)

	response := AuthZResponse{
		Allow: s.plugin.config.FailClosed == false, // Allow on error only if fail-open
		Err:   fmt.Sprintf("%s: %v", message, err),
	}

	if s.plugin.config.FailClosed {
		response.Msg = "Request blocked due to authorization error (fail-closed mode)"
	} else {
		response.Msg = "Request allowed due to authorization error (fail-open mode)"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // Docker expects 200 OK even for errors
	json.NewEncoder(w).Encode(response)
}

// HealthStatus represents the health status of the plugin
type HealthStatus struct {
	Healthy      bool   `json:"healthy"`
	PolicyLoaded bool   `json:"policy_loaded"`
	PolicyName   string `json:"policy_name,omitempty"`
	Uptime       string `json:"uptime,omitempty"`
	Message      string `json:"message,omitempty"`
}
