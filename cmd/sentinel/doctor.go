package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// HealthCheck represents a single diagnostic check
type HealthCheck struct {
	Name        string
	Description string
	Check       func() CheckResult
}

// CheckResult represents the result of a health check
type CheckResult struct {
	Status     string // "ok", "warning", "error"
	Message    string
	Suggestion string
}

// DoctorOutput represents the JSON output format
type DoctorOutput struct {
	Healthy bool                 `json:"healthy"`
	Checks  []DoctorCheckOutput  `json:"checks"`
	Summary DoctorSummary        `json:"summary"`
}

// DoctorCheckOutput represents a single check in JSON
type DoctorCheckOutput struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

// DoctorSummary provides overall statistics
type DoctorSummary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose common issues with your sentinel installation",
	Long: `Run diagnostic checks to identify common configuration and installation issues.

The doctor command checks:
  - Docker daemon connectivity
  - Sentinel configuration and policies
  - Scanner availability (Trivy, Grype, TruffleHog)
  - File permissions
  - Authorization plugin status`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	jsonOutput := isJSONOutput(cmd)

	checks := []HealthCheck{
		{
			Name:        "Docker Daemon",
			Description: "Check if Docker daemon is running and accessible",
			Check:       checkDockerRunning,
		},
		{
			Name:        "Configuration Directory",
			Description: "Check if config directory exists and is accessible",
			Check:       checkConfigDir,
		},
		{
			Name:        "Policies Directory",
			Description: "Check if policies directory exists with valid policies",
			Check:       checkPoliciesDir,
		},
		{
			Name:        "Active Policy",
			Description: "Check if active policy is configured and valid",
			Check:       checkActivePolicy,
		},
		{
			Name:        "Trivy Scanner",
			Description: "Check if Trivy vulnerability scanner is installed",
			Check:       checkTrivy,
		},
		{
			Name:        "Grype Scanner",
			Description: "Check if Grype vulnerability scanner is installed",
			Check:       checkGrype,
		},
		{
			Name:        "TruffleHog Scanner",
			Description: "Check if TruffleHog secret scanner is installed",
			Check:       checkTruffleHog,
		},
		{
			Name:        "Authorization Plugin",
			Description: "Check authorization plugin status",
			Check:       checkAuthzPlugin,
		},
	}

	var results []DoctorCheckOutput
	summary := DoctorSummary{Total: len(checks)}

	if !jsonOutput {
		fmt.Println("Docker Sentinel Doctor")
		fmt.Println("======================")
		fmt.Println()
	}

	allHealthy := true
	for _, check := range checks {
		result := check.Check()

		checkOutput := DoctorCheckOutput{
			Name:       check.Name,
			Status:     result.Status,
			Message:    result.Message,
			Suggestion: result.Suggestion,
		}
		results = append(results, checkOutput)

		switch result.Status {
		case "ok":
			summary.Passed++
		case "warning":
			summary.Warnings++
		case "error":
			summary.Failed++
			allHealthy = false
		}

		if !jsonOutput {
			printCheckResult(check.Name, result)
		}
	}

	if jsonOutput {
		output := DoctorOutput{
			Healthy: allHealthy,
			Checks:  results,
			Summary: summary,
		}
		outputJSON(output, allHealthy)
		if !allHealthy {
			os.Exit(1)
		}
		return nil
	}

	// Print summary
	fmt.Println()
	fmt.Println("Summary")
	fmt.Println("-------")
	fmt.Printf("  Passed:   %d\n", summary.Passed)
	fmt.Printf("  Warnings: %d\n", summary.Warnings)
	fmt.Printf("  Failed:   %d\n", summary.Failed)
	fmt.Println()

	if allHealthy {
		fmt.Println("\033[32mAll checks passed! Sentinel is ready to use.\033[0m")
	} else {
		fmt.Println("\033[31mSome checks failed. Please review the suggestions above.\033[0m")
		os.Exit(1)
	}

	return nil
}

func printCheckResult(name string, result CheckResult) {
	var icon, color string
	switch result.Status {
	case "ok":
		icon = "✓"
		color = "\033[32m"
	case "warning":
		icon = "⚠"
		color = "\033[33m"
	case "error":
		icon = "✗"
		color = "\033[31m"
	}

	fmt.Printf("%s%s\033[0m %s\n", color, icon, name)
	fmt.Printf("    %s\n", result.Message)
	if result.Suggestion != "" {
		fmt.Printf("    \033[36mSuggestion:\033[0m %s\n", result.Suggestion)
	}
	fmt.Println()
}

func checkDockerRunning() CheckResult {
	cmd := exec.Command("docker", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "permission denied") {
			return CheckResult{
				Status:     "error",
				Message:    "Docker daemon is running but permission denied",
				Suggestion: "Run sentinel with sudo or add your user to the docker group",
			}
		}
		return CheckResult{
			Status:     "error",
			Message:    "Docker daemon is not running or not accessible",
			Suggestion: "Start Docker with: sudo systemctl start docker",
		}
	}
	return CheckResult{
		Status:  "ok",
		Message: "Docker daemon is running and accessible",
	}
}

func checkConfigDir() CheckResult {
	configDir := "/etc/sentinel"
	if cfg != nil && cfg.ConfigDir != "" {
		configDir = cfg.ConfigDir
	}

	info, err := os.Stat(configDir)
	if os.IsNotExist(err) {
		return CheckResult{
			Status:     "warning",
			Message:    fmt.Sprintf("Config directory does not exist: %s", configDir),
			Suggestion: "Run: sudo mkdir -p /etc/sentinel",
		}
	}
	if err != nil {
		return CheckResult{
			Status:     "error",
			Message:    fmt.Sprintf("Cannot access config directory: %v", err),
			Suggestion: "Check permissions on " + configDir,
		}
	}
	if !info.IsDir() {
		return CheckResult{
			Status:     "error",
			Message:    fmt.Sprintf("%s exists but is not a directory", configDir),
			Suggestion: "Remove the file and create a directory instead",
		}
	}
	return CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("Config directory exists: %s", configDir),
	}
}

func checkPoliciesDir() CheckResult {
	policiesDir := "/etc/sentinel/policies"
	if cfg != nil && cfg.PoliciesDir != "" {
		policiesDir = cfg.PoliciesDir
	}

	info, err := os.Stat(policiesDir)
	if os.IsNotExist(err) {
		return CheckResult{
			Status:     "warning",
			Message:    fmt.Sprintf("Policies directory does not exist: %s", policiesDir),
			Suggestion: "Sentinel will create default policies on first run",
		}
	}
	if err != nil {
		return CheckResult{
			Status:     "error",
			Message:    fmt.Sprintf("Cannot access policies directory: %v", err),
			Suggestion: "Check permissions on " + policiesDir,
		}
	}
	if !info.IsDir() {
		return CheckResult{
			Status:     "error",
			Message:    fmt.Sprintf("%s exists but is not a directory", policiesDir),
			Suggestion: "Remove the file and create a directory instead",
		}
	}

	// Count policy files
	files, _ := filepath.Glob(filepath.Join(policiesDir, "*.yaml"))
	if len(files) == 0 {
		return CheckResult{
			Status:     "warning",
			Message:    "No policy files found in policies directory",
			Suggestion: "Run: sentinel policy create default --template default",
		}
	}

	return CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("Found %d policy file(s) in %s", len(files), policiesDir),
	}
}

func checkActivePolicy() CheckResult {
	if cfg == nil {
		return CheckResult{
			Status:     "warning",
			Message:    "Configuration not loaded",
			Suggestion: "Ensure config file exists at /etc/sentinel/config.yaml",
		}
	}

	if cfg.ActivePolicy == "" {
		return CheckResult{
			Status:     "warning",
			Message:    "No active policy configured",
			Suggestion: "Set active policy with: sentinel policy use default",
		}
	}

	// Try to load the policy
	if policyMgr != nil {
		_, err := policyMgr.Load(cfg.ActivePolicy)
		if err != nil {
			return CheckResult{
				Status:     "error",
				Message:    fmt.Sprintf("Active policy '%s' cannot be loaded: %v", cfg.ActivePolicy, err),
				Suggestion: "Check policy file or set a different active policy",
			}
		}
	}

	return CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("Active policy: %s", cfg.ActivePolicy),
	}
}

func checkTrivy() CheckResult {
	path, err := exec.LookPath("trivy")
	if err != nil {
		return CheckResult{
			Status:     "warning",
			Message:    "Trivy is not installed",
			Suggestion: "Install with: brew install trivy (or see https://trivy.dev)",
		}
	}

	// Get version
	cmd := exec.Command(path, "version")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Status:  "ok",
			Message: "Trivy is installed at " + path,
		}
	}

	version := strings.TrimSpace(strings.Split(string(output), "\n")[0])
	return CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("Trivy is installed: %s", version),
	}
}

func checkGrype() CheckResult {
	path, err := exec.LookPath("grype")
	if err != nil {
		return CheckResult{
			Status:     "warning",
			Message:    "Grype is not installed",
			Suggestion: "Install with: brew install grype (or see https://github.com/anchore/grype)",
		}
	}

	// Get version
	cmd := exec.Command(path, "version")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Status:  "ok",
			Message: "Grype is installed at " + path,
		}
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version:") || strings.HasPrefix(line, "grype") {
			return CheckResult{
				Status:  "ok",
				Message: fmt.Sprintf("Grype is installed: %s", strings.TrimSpace(line)),
			}
		}
	}

	return CheckResult{
		Status:  "ok",
		Message: "Grype is installed at " + path,
	}
}

func checkTruffleHog() CheckResult {
	path, err := exec.LookPath("trufflehog")
	if err != nil {
		return CheckResult{
			Status:     "warning",
			Message:    "TruffleHog is not installed",
			Suggestion: "Install with: brew install trufflehog",
		}
	}

	// Get version
	cmd := exec.Command(path, "--version")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Status:  "ok",
			Message: "TruffleHog is installed at " + path,
		}
	}

	version := strings.TrimSpace(string(output))
	return CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("TruffleHog is installed: %s", version),
	}
}

func checkAuthzPlugin() CheckResult {
	pidFile := "/var/run/sentinel-authz.pid"

	// Check if PID file exists
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		return CheckResult{
			Status:     "warning",
			Message:    "Authorization plugin is not running",
			Suggestion: "Install with: sudo sentinel authz install --systemd --restart-docker",
		}
	}

	// Read PID and check if process is running
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return CheckResult{
			Status:     "warning",
			Message:    "Cannot read PID file",
			Suggestion: "Check permissions on " + pidFile,
		}
	}

	pid := strings.TrimSpace(string(data))
	procPath := fmt.Sprintf("/proc/%s", pid)
	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return CheckResult{
			Status:     "warning",
			Message:    "PID file exists but process is not running",
			Suggestion: "Restart with: sudo sentinel authz start",
		}
	}

	return CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("Authorization plugin is running (PID: %s)", pid),
	}
}
