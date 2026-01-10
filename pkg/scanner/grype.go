package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
)

// GrypeScanner implements ImageScanner using Grype
type GrypeScanner struct {
	BaseScanner
}

// NewGrypeScanner creates a new Grype scanner
func NewGrypeScanner(cfg *config.Config) *GrypeScanner {
	return &GrypeScanner{
		BaseScanner: NewBaseScanner(cfg),
	}
}

func (g *GrypeScanner) Name() string {
	return "grype"
}

func (g *GrypeScanner) Available() bool {
	return findExecutable("grype") != ""
}

func (g *GrypeScanner) Scan(image string, severityFilter string) (*ScanResult, error) {
	grypePath := findExecutable("grype")
	if grypePath == "" {
		return nil, fmt.Errorf("grype is not installed")
	}

	start := time.Now()

	// Build grype command
	args := []string{
		image,
		"-o", "json",
		"--quiet",
	}

	cmd := exec.Command(grypePath, args...)
	output, err := cmd.Output()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("grype scan failed: %w", err)
		}
	}

	result, err := g.parseOutput(output, severityFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	result.Scanner = g.Name()
	result.Image = image
	result.ScannedAt = time.Now()
	result.ScanDuration = time.Since(start)

	return result, nil
}

// GrypeOutput represents Grype JSON output format
type GrypeOutput struct {
	Matches []GrypeMatch `json:"matches"`
}

type GrypeMatch struct {
	Vulnerability GrypeVuln   `json:"vulnerability"`
	Artifact      GrypeArtifact `json:"artifact"`
}

type GrypeVuln struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Fix         GrypeFix `json:"fix"`
	URLs        []string `json:"urls"`
	CVSS        []GrypeCVSS `json:"cvss"`
}

type GrypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type GrypeCVSS struct {
	Source  string        `json:"source"`
	Type    string        `json:"type"`
	Version string        `json:"version"`
	Vector  string        `json:"vector"`
	Metrics GrypeCVSSMetrics `json:"metrics"`
}

type GrypeCVSSMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func (g *GrypeScanner) parseOutput(output []byte, severityFilter string) (*ScanResult, error) {
	var grypeOut GrypeOutput
	if err := json.Unmarshal(output, &grypeOut); err != nil {
		return nil, err
	}

	result := &ScanResult{}
	severities := make(map[string]bool)
	if severityFilter != "" {
		for _, s := range strings.Split(severityFilter, ",") {
			severities[strings.ToUpper(strings.TrimSpace(s))] = true
		}
	}

	for _, match := range grypeOut.Matches {
		severity := strings.ToUpper(match.Vulnerability.Severity)

		// Apply severity filter
		if len(severities) > 0 && !severities[severity] {
			continue
		}

		v := Vulnerability{
			CVE:         match.Vulnerability.ID,
			Severity:    severity,
			Package:     match.Artifact.Name,
			Version:     match.Artifact.Version,
			Description: truncateDescription(match.Vulnerability.Description),
			References:  match.Vulnerability.URLs,
		}

		// Fixed version
		if len(match.Vulnerability.Fix.Versions) > 0 {
			v.FixedVersion = match.Vulnerability.Fix.Versions[0]
		}

		// CVSS score
		if len(match.Vulnerability.CVSS) > 0 {
			v.CVSSScore = match.Vulnerability.CVSS[0].Metrics.BaseScore
		}

		result.Vulnerabilities = append(result.Vulnerabilities, v)

		// Count by severity
		switch severity {
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

	SortBySeverity(result.Vulnerabilities)
	return result, nil
}
