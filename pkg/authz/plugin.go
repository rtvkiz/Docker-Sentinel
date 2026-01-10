package authz

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
	"github.com/rtvkiz/docker-sentinel/pkg/policy"
)

// getDefaultPoliciesDir returns the policies directory based on priority:
// 1. SENTINEL_CONFIG_DIR environment variable + /policies
// 2. /etc/sentinel/policies (if running as root or if it exists)
// 3. ~/.sentinel/policies (user fallback)
func getDefaultPoliciesDir() string {
	// 1. Environment variable override
	if envDir := os.Getenv("SENTINEL_CONFIG_DIR"); envDir != "" {
		return filepath.Join(envDir, "policies")
	}

	// 2. System-wide config (preferred for enterprise/daemon use)
	systemDir := "/etc/sentinel/policies"
	if os.Geteuid() == 0 {
		return systemDir
	}

	// Check if system config exists (non-root user)
	if _, err := os.Stat(systemDir); err == nil {
		return systemDir
	}

	// 3. User home directory fallback
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".sentinel", "policies")
}

// Plugin implements the Docker authorization plugin
type Plugin struct {
	config    *PluginConfig
	policyMgr *policy.Manager
	evaluator *policy.Evaluator
	converter *Converter
	startTime time.Time
	mu        sync.RWMutex
}

// NewPlugin creates a new authorization plugin
func NewPlugin(config *PluginConfig) (*Plugin, error) {
	p := &Plugin{
		config:    config,
		converter: NewConverter(),
		startTime: time.Now(),
	}

	// Initialize policy manager with proper path resolution
	if config.PoliciesDir == "" {
		config.PoliciesDir = getDefaultPoliciesDir()
	}
	p.policyMgr = policy.NewManager(config.PoliciesDir)

	// Initialize policies directory
	if err := p.policyMgr.Init(); err != nil {
		p.log("warn", "Failed to initialize policies directory: %v", err)
	}

	// Load the active policy
	if err := p.loadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	return p, nil
}

// loadPolicy loads the active policy and creates the evaluator
func (p *Plugin) loadPolicy() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear cache to force reload from disk (important for hot reload)
	p.policyMgr.ClearCache()

	var pol *policy.Policy
	var err error

	// Try to load specified policy, or use active/default
	if p.config.PolicyName != "" {
		pol, err = p.policyMgr.Load(p.config.PolicyName)
	} else {
		// Reload config file to get current active_policy setting
		// This is important for hot reload when user runs "sentinel policy use <name>"
		cfg, cfgErr := config.Load("")
		if cfgErr == nil && cfg.ActivePolicy != "" {
			// Update the manager's active policy from the config file
			if setErr := p.policyMgr.SetActive(cfg.ActivePolicy); setErr != nil {
				p.log("warn", "Failed to set active policy from config: %v", setErr)
			}
		}
		pol, err = p.policyMgr.GetActive()
	}

	if err != nil {
		// Fall back to default policy
		p.log("warn", "Failed to load policy, using default: %v", err)
		pol = policy.Default()
	}

	// Create evaluator
	p.evaluator, err = policy.NewEvaluator(pol, "")
	if err != nil {
		return fmt.Errorf("failed to create evaluator: %w", err)
	}

	p.log("info", "Loaded policy: %s (mode: %s)", pol.Name, pol.Mode)
	return nil
}

// ReloadPolicy reloads the policy configuration
func (p *Plugin) ReloadPolicy() error {
	p.log("info", "Reloading policy configuration...")
	return p.loadPolicy()
}

// AuthZReq handles pre-request authorization
func (p *Plugin) AuthZReq(req *AuthZRequest) *AuthZResponse {
	// Check if this is a security-relevant request
	if !p.converter.IsSecurityRelevant(req) {
		return &AuthZResponse{Allow: true}
	}

	// Convert API request to DockerCommand
	cmd, err := p.converter.Convert(req)
	if err != nil {
		return p.handleConversionError(req, err)
	}

	// Evaluate against policy
	p.mu.RLock()
	evaluator := p.evaluator
	p.mu.RUnlock()

	if evaluator == nil {
		return p.handleError(req, "no policy evaluator available")
	}

	result, err := evaluator.Evaluate(cmd)
	if err != nil {
		return p.handleEvaluationError(req, err)
	}

	// Determine response
	if result.Allowed {
		// Check for warnings
		if len(result.Warnings) > 0 {
			return &AuthZResponse{
				Allow: true,
				Msg:   p.formatWarnings(result.Warnings),
			}
		}
		return &AuthZResponse{Allow: true}
	}

	// Request denied
	return &AuthZResponse{
		Allow: false,
		Msg:   p.formatDenialMessage(result),
	}
}

// AuthZRes handles post-request authorization
func (p *Plugin) AuthZRes(req *AuthZRequest) *AuthZResponse {
	// Post-request authorization - we typically allow all
	// This could be extended to filter response data
	return &AuthZResponse{Allow: true}
}

// handleConversionError handles errors during request conversion
func (p *Plugin) handleConversionError(req *AuthZRequest, err error) *AuthZResponse {
	p.log("error", "Request conversion failed: %v (URI: %s)", err, req.RequestURI)

	if p.config.FailClosed {
		return &AuthZResponse{
			Allow: false,
			Msg:   fmt.Sprintf("Request blocked: failed to parse request (%v)", err),
			Err:   err.Error(),
		}
	}

	return &AuthZResponse{
		Allow: true,
		Msg:   "Request allowed due to conversion error (fail-open mode)",
	}
}

// handleEvaluationError handles errors during policy evaluation
func (p *Plugin) handleEvaluationError(req *AuthZRequest, err error) *AuthZResponse {
	p.log("error", "Policy evaluation failed: %v (URI: %s)", err, req.RequestURI)

	if p.config.FailClosed {
		return &AuthZResponse{
			Allow: false,
			Msg:   fmt.Sprintf("Request blocked: policy evaluation failed (%v)", err),
			Err:   err.Error(),
		}
	}

	return &AuthZResponse{
		Allow: true,
		Msg:   "Request allowed due to evaluation error (fail-open mode)",
	}
}

// handleError handles generic errors
func (p *Plugin) handleError(req *AuthZRequest, message string) *AuthZResponse {
	p.log("error", "%s (URI: %s)", message, req.RequestURI)

	if p.config.FailClosed {
		return &AuthZResponse{
			Allow: false,
			Msg:   fmt.Sprintf("Request blocked: %s", message),
		}
	}

	return &AuthZResponse{
		Allow: true,
		Msg:   fmt.Sprintf("Request allowed despite error: %s (fail-open mode)", message),
	}
}

// formatDenialMessage formats a denial message from the evaluation result
func (p *Plugin) formatDenialMessage(result *policy.EvaluationResult) string {
	var sb strings.Builder

	// Header with risk score
	sb.WriteString(fmt.Sprintf("\n\n  ⛔ BLOCKED BY SENTINEL (Risk Score: %d/100)\n", result.Score))
	sb.WriteString("  ─────────────────────────────────────────\n")

	// Violations
	if len(result.Violations) > 0 {
		for _, v := range result.Violations {
			icon := "⚠️"
			if v.Severity == "critical" {
				icon = "🚫"
			} else if v.Severity == "high" {
				icon = "❌"
			}
			sb.WriteString(fmt.Sprintf("  %s [%s] %s\n", icon, strings.ToUpper(v.Severity), v.Message))
		}
	}

	// Suggested fixes
	if len(result.Mitigations) > 0 {
		sb.WriteString("\n  💡 Suggested fixes:\n")
		for _, m := range result.Mitigations {
			sb.WriteString(fmt.Sprintf("     → %s\n", m))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// formatWarnings formats warnings from the evaluation result
func (p *Plugin) formatWarnings(warnings []policy.Violation) string {
	var parts []string
	for _, w := range warnings {
		parts = append(parts, fmt.Sprintf("[%s] %s", w.Severity, w.Message))
	}
	return "Warnings: " + strings.Join(parts, "; ")
}

// HealthCheck returns the health status of the plugin
func (p *Plugin) HealthCheck() HealthStatus {
	p.mu.RLock()
	evaluator := p.evaluator
	p.mu.RUnlock()

	status := HealthStatus{
		Healthy:      evaluator != nil,
		PolicyLoaded: evaluator != nil,
		PolicyName:   p.config.PolicyName,
		Uptime:       time.Since(p.startTime).Round(time.Second).String(),
	}

	if !status.Healthy {
		status.Message = "No policy evaluator available"
	} else {
		status.Message = "Plugin is healthy"
	}

	return status
}

// log logs a message with the specified level
func (p *Plugin) log(level, format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	switch level {
	case "error":
		fmt.Fprintf(os.Stderr, "[%s] ERROR: %s\n", timestamp, message)
	case "warn":
		fmt.Fprintf(os.Stderr, "[%s] WARN: %s\n", timestamp, message)
	case "info":
		fmt.Printf("[%s] INFO: %s\n", timestamp, message)
	case "debug":
		if p.config.LogLevel == "debug" {
			fmt.Printf("[%s] DEBUG: %s\n", timestamp, message)
		}
	}
}

// Close cleans up plugin resources
func (p *Plugin) Close() error {
	return nil
}
