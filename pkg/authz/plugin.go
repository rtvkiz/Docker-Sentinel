package authz

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/audit"
	"github.com/rtvkiz/docker-sentinel/pkg/config"
	"github.com/rtvkiz/docker-sentinel/pkg/interceptor"
	"github.com/rtvkiz/docker-sentinel/pkg/policy"
	"github.com/rtvkiz/docker-sentinel/pkg/scanner"
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
	config           *PluginConfig
	policyMgr        *policy.Manager
	evaluator        *policy.Evaluator
	converter        *Converter
	auditLogger      *audit.Logger
	secretScanner    *scanner.TruffleHogScanner
	activePolicyName string
	startTime        time.Time
	mu               sync.RWMutex
}

// NewPlugin creates a new authorization plugin
func NewPlugin(pluginCfg *PluginConfig) (*Plugin, error) {
	p := &Plugin{
		config:    pluginCfg,
		converter: NewConverter(),
		startTime: time.Now(),
	}

	// Initialize policy manager with proper path resolution
	if pluginCfg.PoliciesDir == "" {
		pluginCfg.PoliciesDir = getDefaultPoliciesDir()
	}
	p.policyMgr = policy.NewManager(pluginCfg.PoliciesDir)

	// Initialize policies directory
	if err := p.policyMgr.Init(); err != nil {
		p.log("warn", "Failed to initialize policies directory: %v", err)
	}

	// Load the active policy
	if err := p.loadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	// Initialize secret scanner (for push/build operations)
	cfg, err := config.Load("")
	if err != nil {
		p.log("warn", "Failed to load config for secret scanner: %v", err)
	} else {
		p.secretScanner = scanner.NewTruffleHogScanner(cfg)
		if p.secretScanner.Available() {
			p.log("info", "Secret scanning enabled (TruffleHog available)")
		} else {
			p.log("info", "Secret scanning disabled (TruffleHog not installed)")
		}
	}

	// Initialize audit logger
	if pluginCfg.AuditEnabled {
		auditDir := pluginCfg.AuditDir
		if auditDir == "" {
			auditDir = "/etc/sentinel/audit"
		}
		logger, err := audit.NewLogger(auditDir)
		if err != nil {
			p.log("warn", "Failed to initialize audit logger: %v", err)
		} else {
			p.auditLogger = logger
			p.log("info", "Audit logging enabled (dir: %s)", auditDir)
		}
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
		// Explicit policy name was provided at startup, use it
		p.log("info", "Using explicit policy from startup flag: %s", p.config.PolicyName)
		pol, err = p.policyMgr.Load(p.config.PolicyName)
	} else {
		// No explicit policy - reload active_policy from config file
		// This is critical for hot reload when user runs "sentinel policy use <name>"
		cfg, cfgErr := config.Load("")
		if cfgErr != nil {
			p.log("warn", "Failed to load config during reload: %v", cfgErr)
		} else {
			p.log("info", "Config reloaded, active_policy from file: %s", cfg.ActivePolicy)
			if cfg.ActivePolicy != "" {
				if setErr := p.policyMgr.SetActive(cfg.ActivePolicy); setErr != nil {
					p.log("warn", "Failed to set active policy from config: %v", setErr)
				}
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

	// Store active policy name for audit logging
	p.activePolicyName = pol.Name

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
	// Check if this is a build response - scan the built image for secrets
	if p.isBuildResponse(req) {
		imageTag := p.extractBuildTag(req)
		if imageTag != "" {
			if secretResult := p.scanImageForSecrets(imageTag); secretResult != nil {
				if !secretResult.Allowed {
					// Secrets found in built image - log warning
					// Note: We can't truly "block" here since the build already completed
					// But we log it prominently so it shows in the daemon output
					p.log("warn", "SECRETS DETECTED in built image %s: %s", imageTag, secretResult.Message)
					// Return a warning message (Docker will display this)
					return &AuthZResponse{
						Allow: true, // Can't block after build, but warn
						Msg:   fmt.Sprintf("⚠️ WARNING: Secrets detected in built image %s. Do not push this image!", imageTag),
					}
				}
			}
		}
	}

	// Post-request authorization - allow all
	return &AuthZResponse{Allow: true}
}

// isBuildResponse checks if this is a response to a build request
func (p *Plugin) isBuildResponse(req *AuthZRequest) bool {
	return strings.Contains(req.RequestURI, "/build")
}

// extractBuildTag extracts the image tag from a build request
func (p *Plugin) extractBuildTag(req *AuthZRequest) string {
	// Parse the request URI properly to get the 't' (tag) parameter
	// Example: /v1.47/build?t=myapp:latest&cpuperiod=0&...
	parsedURL, err := url.Parse(req.RequestURI)
	if err != nil {
		return ""
	}

	// Get the 't' query parameter (image tag)
	tag := parsedURL.Query().Get("t")
	if tag == "" {
		return ""
	}

	// URL decode if needed
	if decoded, err := url.QueryUnescape(tag); err == nil {
		return decoded
	}
	return tag
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
	if p.auditLogger != nil {
		return p.auditLogger.Close()
	}
	return nil
}

// LogAuditEntry logs an audit entry if audit logging is enabled
func (p *Plugin) LogAuditEntry(entry *audit.Entry) {
	if p.auditLogger == nil {
		return
	}

	if err := p.auditLogger.Log(entry); err != nil {
		p.log("error", "Failed to log audit entry: %v", err)
	}
}

// AuthZReqResult contains the authorization result with additional audit info
type AuthZReqResult struct {
	Response   *AuthZResponse
	Image      string
	Command    string
	RiskScore  int
	PolicyName string
	Violations []string
}

// AuthZReqWithAudit handles pre-request authorization and returns audit info
func (p *Plugin) AuthZReqWithAudit(req *AuthZRequest) *AuthZReqResult {
	result := &AuthZReqResult{
		Response: &AuthZResponse{Allow: true},
	}

	// Check if this is a security-relevant request
	if !p.converter.IsSecurityRelevant(req) {
		return result
	}

	// Convert API request to DockerCommand
	cmd, err := p.converter.Convert(req)
	if err != nil {
		result.Response = p.handleConversionError(req, err)
		return result
	}

	// Capture command info for audit
	result.Image = cmd.Image
	result.Command = p.formatCommandSummary(cmd)

	// Evaluate against policy
	p.mu.RLock()
	evaluator := p.evaluator
	p.mu.RUnlock()

	if evaluator == nil {
		result.Response = p.handleError(req, "no policy evaluator available")
		return result
	}

	evalResult, err := evaluator.Evaluate(cmd)
	if err != nil {
		result.Response = p.handleEvaluationError(req, err)
		return result
	}

	// Capture evaluation info for audit
	result.RiskScore = evalResult.Score
	result.PolicyName = p.activePolicyName
	for _, v := range evalResult.Violations {
		result.Violations = append(result.Violations, v.Message)
	}
	for _, w := range evalResult.Warnings {
		result.Violations = append(result.Violations, w.Message)
	}

	// Secret scanning for push operations (scan before allowing push)
	if cmd.Action == "push" && cmd.Image != "" && evalResult.Allowed {
		if secretResult := p.scanImageForSecrets(cmd.Image); secretResult != nil {
			if !secretResult.Allowed {
				// Secrets found - block the push
				result.Response = &AuthZResponse{
					Allow: false,
					Msg:   secretResult.Message,
				}
				result.Violations = append(result.Violations, secretResult.Message)
				result.RiskScore += secretResult.ScoreImpact
				return result
			} else if secretResult.Message != "" {
				// Warnings only
				result.Violations = append(result.Violations, secretResult.Message)
			}
		}
	}

	// Determine response
	if evalResult.Allowed {
		// Check for warnings
		if len(evalResult.Warnings) > 0 {
			result.Response = &AuthZResponse{
				Allow: true,
				Msg:   p.formatWarnings(evalResult.Warnings),
			}
		} else {
			result.Response = &AuthZResponse{Allow: true}
		}
	} else {
		// Request denied
		result.Response = &AuthZResponse{
			Allow: false,
			Msg:   p.formatDenialMessage(evalResult),
		}
	}

	return result
}

// SecretScanResult contains the result of a secret scan
type SecretScanResult struct {
	Allowed     bool
	Message     string
	ScoreImpact int
}

// scanImageForSecrets scans an image for secrets using TruffleHog
func (p *Plugin) scanImageForSecrets(image string) *SecretScanResult {
	if p.secretScanner == nil || !p.secretScanner.Available() {
		return nil // Scanner not available, skip
	}

	p.log("info", "Scanning image for secrets: %s", image)

	result, err := p.secretScanner.ScanSecrets(image)
	if err != nil {
		p.log("warn", "Secret scan failed for %s: %v", image, err)
		return nil // Don't block on scan failure
	}

	if result.SecretsFound == 0 {
		p.log("info", "No secrets found in image: %s", image)
		return &SecretScanResult{Allowed: true}
	}

	// Count by severity
	var critical, high, verified int
	for _, s := range result.Secrets {
		if s.Verified {
			verified++
		}
		switch s.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		}
	}

	// Verified secrets always block
	if verified > 0 {
		msg := fmt.Sprintf("\n\n  🔐 SECRETS DETECTED - PUSH BLOCKED\n  ─────────────────────────────────────────\n  🚫 Found %d VERIFIED (active) secret(s) in image!\n  These are confirmed valid credentials.\n\n  💡 Remove secrets and rebuild the image before pushing.\n", verified)
		return &SecretScanResult{
			Allowed:     false,
			Message:     msg,
			ScoreImpact: 50,
		}
	}

	// Critical/high secrets block
	if critical > 0 || high > 0 {
		msg := fmt.Sprintf("\n\n  🔐 SECRETS DETECTED - PUSH BLOCKED\n  ─────────────────────────────────────────\n  ❌ Found %d critical and %d high-severity secret(s)\n\n  💡 Review findings and remove secrets before pushing.\n     Use 'sentinel scan-secrets %s' for details.\n", critical, high, image)
		return &SecretScanResult{
			Allowed:     false,
			Message:     msg,
			ScoreImpact: 40,
		}
	}

	// Medium severity - warn only
	return &SecretScanResult{
		Allowed: true,
		Message: fmt.Sprintf("Found %d medium-severity potential secret(s) in image", result.SecretsFound),
	}
}

// formatCommandSummary creates a readable Docker command from the parsed command
func (p *Plugin) formatCommandSummary(cmd *interceptor.DockerCommand) string {
	var parts []string
	parts = append(parts, "docker", cmd.Action)

	// Add key flags based on action
	switch cmd.Action {
	case "run", "create":
		if cmd.Privileged {
			parts = append(parts, "--privileged")
		}
		if cmd.NetworkMode == "host" {
			parts = append(parts, "--network", "host")
		}
		if cmd.PIDMode == "host" {
			parts = append(parts, "--pid", "host")
		}
		if cmd.User != "" {
			parts = append(parts, "--user", cmd.User)
		}
		for _, v := range cmd.Volumes {
			// Format volume mount as source:destination
			volStr := v.Source
			if v.Destination != "" {
				volStr = v.Source + ":" + v.Destination
			}
			parts = append(parts, "-v", volStr)
		}
		for _, cap := range cmd.Capabilities.Add {
			parts = append(parts, "--cap-add", cap)
		}
		if cmd.Image != "" {
			parts = append(parts, cmd.Image)
		}
		if len(cmd.Command) > 0 {
			parts = append(parts, cmd.Command...)
		}

	case "exec":
		if cmd.Privileged {
			parts = append(parts, "--privileged")
		}
		if cmd.User != "" {
			parts = append(parts, "--user", cmd.User)
		}
		if cmd.ContainerName != "" {
			parts = append(parts, cmd.ContainerName)
		}
		if len(cmd.Command) > 0 {
			parts = append(parts, cmd.Command...)
		}

	case "build":
		if cmd.Image != "" {
			parts = append(parts, "-t", cmd.Image)
		}

	case "push", "pull":
		if cmd.Image != "" {
			parts = append(parts, cmd.Image)
		}

	default:
		// For other actions, just include the image/container if available
		if cmd.Image != "" {
			parts = append(parts, cmd.Image)
		}
		if cmd.ContainerName != "" {
			parts = append(parts, cmd.ContainerName)
		}
	}

	return strings.Join(parts, " ")
}
