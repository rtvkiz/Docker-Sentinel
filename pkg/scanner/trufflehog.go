package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
)

// TruffleHogScanner implements secret scanning using TruffleHog
type TruffleHogScanner struct {
	BaseScanner
}

// NewTruffleHogScanner creates a new TruffleHog scanner
func NewTruffleHogScanner(cfg *config.Config) *TruffleHogScanner {
	return &TruffleHogScanner{
		BaseScanner: NewBaseScanner(cfg),
	}
}

func (t *TruffleHogScanner) Name() string {
	return "trufflehog"
}

func (t *TruffleHogScanner) Available() bool {
	return findExecutable("trufflehog") != ""
}

// SecretScanResult contains the results of a secret scan
type SecretScanResult struct {
	Scanner      string
	Image        string
	ScannedAt    time.Time
	ScanDuration time.Duration
	SecretsFound int
	Secrets      []SecretFinding
}

// SecretFinding represents a discovered secret
type SecretFinding struct {
	// Type of secret (aws_key, github_token, private_key, etc.)
	DetectorType string `json:"DetectorType"`

	// Name of the detector
	DetectorName string `json:"DetectorName"`

	// Whether the secret was verified as valid
	Verified bool `json:"Verified"`

	// Raw secret value (redacted for display)
	Raw string `json:"Raw"`

	// File where the secret was found
	SourceMetadata SourceMetadata `json:"SourceMetadata"`

	// Severity based on secret type and verification
	Severity string
}

// SourceMetadata contains information about where the secret was found
type SourceMetadata struct {
	Data SourceData `json:"Data"`
}

type SourceData struct {
	Docker DockerSource `json:"Docker"`
}

type DockerSource struct {
	Image string `json:"image"`
	Layer string `json:"layer"`
	File  string `json:"file"`
}

// ScanSecrets scans an image for secrets using TruffleHog
func (t *TruffleHogScanner) ScanSecrets(image string) (*SecretScanResult, error) {
	trufflehogPath := findExecutable("trufflehog")
	if trufflehogPath == "" {
		return nil, fmt.Errorf("trufflehog is not installed. Install with: pip install trufflehog or brew install trufflehog")
	}

	start := time.Now()

	// Run trufflehog docker scan
	args := []string{
		"docker",
		"--image", image,
		"--json",
		"--no-update",
	}

	cmd := exec.Command(trufflehogPath, args...)
	output, err := cmd.Output()

	// TruffleHog returns non-zero if secrets found, but we still get output
	if err != nil && len(output) == 0 {
		// Check if it's just "no secrets found"
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 0 || len(exitErr.Stderr) == 0 {
				// No secrets found
				return &SecretScanResult{
					Scanner:      t.Name(),
					Image:        image,
					ScannedAt:    time.Now(),
					ScanDuration: time.Since(start),
					SecretsFound: 0,
					Secrets:      []SecretFinding{},
				}, nil
			}
		}
		return nil, fmt.Errorf("trufflehog scan failed: %w", err)
	}

	result := &SecretScanResult{
		Scanner:      t.Name(),
		Image:        image,
		ScannedAt:    time.Now(),
		ScanDuration: time.Since(start),
	}

	// Parse JSON output (one JSON object per line)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var finding SecretFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}

		// Set severity based on verification and type
		finding.Severity = t.determineSeverity(finding)

		// Redact the actual secret value
		if len(finding.Raw) > 8 {
			finding.Raw = finding.Raw[:4] + "****" + finding.Raw[len(finding.Raw)-4:]
		} else {
			finding.Raw = "****"
		}

		result.Secrets = append(result.Secrets, finding)
	}

	result.SecretsFound = len(result.Secrets)
	return result, nil
}

func (t *TruffleHogScanner) determineSeverity(finding SecretFinding) string {
	// Verified secrets are always critical
	if finding.Verified {
		return "CRITICAL"
	}

	// High-risk secret types
	highRisk := map[string]bool{
		"AWS":                 true,
		"AWSSessionKey":       true,
		"Github":              true,
		"GithubApp":           true,
		"GitLab":              true,
		"Slack":               true,
		"SlackWebhook":        true,
		"Stripe":              true,
		"PrivateKey":          true,
		"RSAPrivateKey":       true,
		"SSHPrivateKey":       true,
		"PGPPrivateKey":       true,
		"GoogleCloud":         true,
		"Azure":               true,
		"HerokuAPIKey":        true,
		"SendGrid":            true,
		"Twilio":              true,
		"JWT":                 true,
		"DatabaseConnection":  true,
		"MongoDBConnection":   true,
		"PostgresConnection":  true,
		"MySQLConnection":     true,
	}

	if highRisk[finding.DetectorType] {
		return "HIGH"
	}

	return "MEDIUM"
}

// PrintSecretScanResult prints the results in a formatted way
func PrintSecretScanResult(result *SecretScanResult) {
	fmt.Printf("\nSecret Scan: %s\n", result.Scanner)
	fmt.Printf("Image: %s\n", result.Image)
	fmt.Printf("Scanned: %s (took %s)\n", result.ScannedAt.Format("2006-01-02 15:04:05"), result.ScanDuration.Round(time.Second))
	fmt.Println()

	if result.SecretsFound == 0 {
		fmt.Println("\033[32m✓ No secrets found\033[0m")
		return
	}

	fmt.Printf("\033[31m✗ Found %d secret(s)!\033[0m\n\n", result.SecretsFound)

	// Count by severity
	critical, high, medium := 0, 0, 0
	for _, s := range result.Secrets {
		switch s.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}

	fmt.Printf("  Critical: %d\n", critical)
	fmt.Printf("  High:     %d\n", high)
	fmt.Printf("  Medium:   %d\n", medium)
	fmt.Println()

	fmt.Println("Details:")
	for i, secret := range result.Secrets {
		if i >= 10 {
			fmt.Printf("  ... and %d more\n", result.SecretsFound-10)
			break
		}

		var severityColor string
		switch secret.Severity {
		case "CRITICAL":
			severityColor = "\033[31m"
		case "HIGH":
			severityColor = "\033[33m"
		default:
			severityColor = "\033[36m"
		}

		verified := ""
		if secret.Verified {
			verified = " \033[31m[VERIFIED]\033[0m"
		}

		file := secret.SourceMetadata.Data.Docker.File
		if file == "" {
			file = "unknown"
		}

		fmt.Printf("  %s[%s]\033[0m %s%s\n", severityColor, secret.Severity, secret.DetectorType, verified)
		fmt.Printf("         File: %s\n", file)
		fmt.Printf("         Preview: %s\n", secret.Raw)
	}
}
