package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
)

// TrivyScanner implements ImageScanner using Trivy
type TrivyScanner struct {
	BaseScanner
}

// NewTrivyScanner creates a new Trivy scanner
func NewTrivyScanner(cfg *config.Config) *TrivyScanner {
	return &TrivyScanner{
		BaseScanner: NewBaseScanner(cfg),
	}
}

func (t *TrivyScanner) Name() string {
	return "trivy"
}

func (t *TrivyScanner) Available() bool {
	return findExecutable("trivy") != ""
}

// findExecutable searches for an executable in PATH and common install locations
func findExecutable(name string) string {
	// Try PATH first
	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	// Check common installation paths
	commonPaths := []string{
		"/usr/local/bin/" + name,
		"/usr/bin/" + name,
		"/home/linuxbrew/.linuxbrew/bin/" + name,
		"/opt/homebrew/bin/" + name,
		"/snap/bin/" + name,
	}

	for _, p := range commonPaths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}

	return ""
}

func (t *TrivyScanner) Scan(image string, severityFilter string) (*ScanResult, error) {
	trivyPath := findExecutable("trivy")
	if trivyPath == "" {
		return nil, fmt.Errorf("trivy is not installed")
	}

	start := time.Now()

	// Build trivy command
	args := []string{
		"image",
		"--format", "json",
		"--quiet",
	}

	if severityFilter != "" {
		args = append(args, "--severity", severityFilter)
	}

	args = append(args, image)

	cmd := exec.Command(trivyPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Trivy returns non-zero on vulnerabilities found, check if we got output
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy scan failed: %w", err)
		}
	}

	result, err := t.parseOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	result.Scanner = t.Name()
	result.Image = image
	result.ScannedAt = time.Now()
	result.ScanDuration = time.Since(start)

	return result, nil
}

// TrivyOutput represents Trivy JSON output format
type TrivyOutput struct {
	Results []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string            `json:"Target"`
	Vulnerabilities []TrivyVuln       `json:"Vulnerabilities"`
}

type TrivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
	CVSS             map[string]TrivyCVSS `json:"CVSS"`
}

type TrivyCVSS struct {
	V3Score float64 `json:"V3Score"`
}

func (t *TrivyScanner) parseOutput(output []byte) (*ScanResult, error) {
	var trivyOut TrivyOutput
	if err := json.Unmarshal(output, &trivyOut); err != nil {
		return nil, err
	}

	result := &ScanResult{}

	for _, res := range trivyOut.Results {
		for _, vuln := range res.Vulnerabilities {
			v := Vulnerability{
				CVE:          vuln.VulnerabilityID,
				Severity:     strings.ToUpper(vuln.Severity),
				Package:      vuln.PkgName,
				Version:      vuln.InstalledVersion,
				FixedVersion: vuln.FixedVersion,
				Description:  truncateDescription(vuln.Description),
				References:   vuln.References,
			}

			// Extract CVSS score
			if nvd, ok := vuln.CVSS["nvd"]; ok {
				v.CVSSScore = nvd.V3Score
			}

			result.Vulnerabilities = append(result.Vulnerabilities, v)

			// Count by severity
			switch v.Severity {
			case "CRITICAL":
				result.TotalCritical++
			case "HIGH":
				result.TotalHigh++
			case "MEDIUM":
				result.TotalMedium++
			case "LOW":
				result.TotalLow++
			}
		}
	}

	SortBySeverity(result.Vulnerabilities)
	return result, nil
}

func truncateDescription(desc string) string {
	if len(desc) > 200 {
		return desc[:197] + "..."
	}
	return desc
}
