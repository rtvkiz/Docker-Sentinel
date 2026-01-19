package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/rules"
	"github.com/rtvkiz/docker-sentinel/pkg/scanner"
	"github.com/spf13/cobra"
)

// JSONOutput is the standard wrapper for JSON output
type JSONOutput struct {
	Success   bool        `json:"success"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
	Error     *JSONError  `json:"error,omitempty"`
}

// JSONError represents an error in JSON format
type JSONError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// ValidationOutput represents validation results in JSON format
type ValidationOutput struct {
	Allowed     bool              `json:"allowed"`
	RiskScore   int               `json:"risk_score"`
	MaxScore    int               `json:"max_score"`
	Command     string            `json:"command"`
	Risks       []RiskOutput      `json:"risks,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	Mitigations []string          `json:"mitigations,omitempty"`
}

// RiskOutput represents a risk in JSON format
type RiskOutput struct {
	Level       string `json:"level"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// ScanOutput represents scan results in JSON format
type ScanOutput struct {
	Image       string                    `json:"image"`
	Scanners    []string                  `json:"scanners"`
	Results     []*scanner.ScanResult     `json:"results"`
	Summary     *ScanSummary              `json:"summary"`
	ThresholdExceeded bool                `json:"threshold_exceeded"`
}

// ScanSummary provides aggregate scan statistics
type ScanSummary struct {
	TotalCritical int `json:"total_critical"`
	TotalHigh     int `json:"total_high"`
	TotalMedium   int `json:"total_medium"`
	TotalLow      int `json:"total_low"`
}

// SecretScanOutput represents secret scan results in JSON format
type SecretScanOutput struct {
	Image        string                   `json:"image"`
	SecretsFound int                      `json:"secrets_found"`
	Secrets      []scanner.SecretFinding  `json:"secrets,omitempty"`
	Verified     int                      `json:"verified_count"`
}

// VersionOutput represents version info in JSON format
type VersionOutput struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// isJSONOutput checks if JSON output is requested
func isJSONOutput(cmd *cobra.Command) bool {
	jsonFlag, _ := cmd.Flags().GetBool("json")
	return jsonFlag
}

// outputJSON writes JSON output to stdout
func outputJSON(data interface{}, success bool) {
	output := JSONOutput{
		Success:   success,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      data,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

// outputJSONError writes a JSON error to stderr
func outputJSONError(code, message, details string) {
	output := JSONOutput{
		Success:   false,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Error: &JSONError{
			Code:    code,
			Message: message,
			Details: details,
		},
	}

	encoder := json.NewEncoder(os.Stderr)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

// convertValidationResult converts rules.ValidationResult to JSON-friendly format
func convertValidationResult(result *rules.ValidationResult, command string, maxScore int) *ValidationOutput {
	output := &ValidationOutput{
		Allowed:     result.Allowed,
		RiskScore:   result.Score,
		MaxScore:    maxScore,
		Command:     command,
		Mitigations: result.Mitigations,
	}

	for _, risk := range result.Risks {
		output.Risks = append(output.Risks, RiskOutput{
			Level:       risk.Level,
			Category:    risk.Category,
			Description: risk.Description,
		})
	}

	for _, warning := range result.Warnings {
		output.Warnings = append(output.Warnings, warning.Message)
	}

	return output
}

// aggregateScanResults creates a summary from multiple scan results
func aggregateScanResults(results []*scanner.ScanResult) *ScanSummary {
	summary := &ScanSummary{}

	// Use max values from all scanners
	for _, r := range results {
		if r.TotalCritical > summary.TotalCritical {
			summary.TotalCritical = r.TotalCritical
		}
		if r.TotalHigh > summary.TotalHigh {
			summary.TotalHigh = r.TotalHigh
		}
		if r.TotalMedium > summary.TotalMedium {
			summary.TotalMedium = r.TotalMedium
		}
		if r.TotalLow > summary.TotalLow {
			summary.TotalLow = r.TotalLow
		}
	}

	return summary
}

// printError prints an error message (used for non-JSON output)
func printError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\033[31mError:\033[0m "+format+"\n", args...)
}
