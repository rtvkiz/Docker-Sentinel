package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
)

// DockerScoutScanner implements ImageScanner using Docker Scout
type DockerScoutScanner struct {
	BaseScanner
}

// NewDockerScoutScanner creates a new Docker Scout scanner
func NewDockerScoutScanner(cfg *config.Config) *DockerScoutScanner {
	return &DockerScoutScanner{
		BaseScanner: NewBaseScanner(cfg),
	}
}

func (d *DockerScoutScanner) Name() string {
	return "docker-scout"
}

func (d *DockerScoutScanner) Available() bool {
	// Check if docker scout plugin is available
	cmd := exec.Command("docker", "scout", "version")
	return cmd.Run() == nil
}

func (d *DockerScoutScanner) Scan(image string, severityFilter string) (*ScanResult, error) {
	if !d.Available() {
		return nil, fmt.Errorf("docker scout is not installed")
	}

	start := time.Now()

	// Build docker scout command
	args := []string{
		"scout", "cves",
		image,
		"--format", "json",
	}

	if severityFilter != "" {
		// Docker Scout uses lowercase severity
		args = append(args, "--only-severity", strings.ToLower(severityFilter))
	}

	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("docker scout scan failed: %w", err)
		}
	}

	result, err := d.parseOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse docker scout output: %w", err)
	}

	result.Scanner = d.Name()
	result.Image = image
	result.ScannedAt = time.Now()
	result.ScanDuration = time.Since(start)

	return result, nil
}

// ScoutOutput represents Docker Scout JSON output format
type ScoutOutput struct {
	Vulnerabilities []ScoutVuln `json:"vulnerabilities"`
}

type ScoutVuln struct {
	ID          string         `json:"id"`
	Severity    string         `json:"severity"`
	Description string         `json:"description"`
	CVSS        ScoutCVSS      `json:"cvss"`
	Package     ScoutPackage   `json:"package"`
	Fix         ScoutFix       `json:"fix"`
	Links       []string       `json:"links"`
}

type ScoutCVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

type ScoutPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

type ScoutFix struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

func (d *DockerScoutScanner) parseOutput(output []byte) (*ScanResult, error) {
	var scoutOut ScoutOutput
	if err := json.Unmarshal(output, &scoutOut); err != nil {
		// Docker Scout might have different output format, try alternative
		return d.parseAlternativeOutput(output)
	}

	result := &ScanResult{}

	for _, vuln := range scoutOut.Vulnerabilities {
		severity := strings.ToUpper(vuln.Severity)

		v := Vulnerability{
			CVE:          vuln.ID,
			Severity:     severity,
			Package:      vuln.Package.Name,
			Version:      vuln.Package.Version,
			FixedVersion: vuln.Fix.Version,
			Description:  truncateDescription(vuln.Description),
			CVSSScore:    vuln.CVSS.Score,
			References:   vuln.Links,
		}

		result.Vulnerabilities = append(result.Vulnerabilities, v)

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

// ScoutAlternativeOutput for different Docker Scout versions
type ScoutAlternativeOutput struct {
	Image   ScoutImage `json:"image"`
	Results []ScoutResult `json:"results"`
}

type ScoutImage struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type ScoutResult struct {
	Target          string      `json:"target"`
	Vulnerabilities []ScoutVuln `json:"vulnerabilities"`
}

func (d *DockerScoutScanner) parseAlternativeOutput(output []byte) (*ScanResult, error) {
	var altOut ScoutAlternativeOutput
	if err := json.Unmarshal(output, &altOut); err != nil {
		return nil, err
	}

	result := &ScanResult{}

	for _, res := range altOut.Results {
		for _, vuln := range res.Vulnerabilities {
			severity := strings.ToUpper(vuln.Severity)

			v := Vulnerability{
				CVE:          vuln.ID,
				Severity:     severity,
				Package:      vuln.Package.Name,
				Version:      vuln.Package.Version,
				FixedVersion: vuln.Fix.Version,
				Description:  truncateDescription(vuln.Description),
				CVSSScore:    vuln.CVSS.Score,
				References:   vuln.Links,
			}

			result.Vulnerabilities = append(result.Vulnerabilities, v)

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
	}

	SortBySeverity(result.Vulnerabilities)
	return result, nil
}
