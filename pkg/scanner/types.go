package scanner

import (
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
)

// ImageScanner interface for vulnerability scanners
type ImageScanner interface {
	// Name returns the scanner name
	Name() string

	// Available checks if the scanner is installed
	Available() bool

	// Scan scans an image and returns results
	Scan(image string, severityFilter string) (*ScanResult, error)
}

// ScanResult contains the results of a vulnerability scan
type ScanResult struct {
	// Scanner that produced these results
	Scanner string

	// Image that was scanned
	Image string

	// Time of scan
	ScannedAt time.Time

	// Vulnerability counts by severity
	TotalCritical int
	TotalHigh     int
	TotalMedium   int
	TotalLow      int

	// Detailed vulnerability list
	Vulnerabilities []Vulnerability

	// Scan metadata
	ScanDuration time.Duration
	FromCache    bool
}

// Vulnerability represents a single CVE
type Vulnerability struct {
	// CVE identifier
	CVE string `json:"cve"`

	// Severity level
	Severity string `json:"severity"`

	// Affected package name
	Package string `json:"package"`

	// Installed version
	Version string `json:"version"`

	// Fixed version (if available)
	FixedVersion string `json:"fixed_version"`

	// Human-readable description
	Description string `json:"description"`

	// CVSS score
	CVSSScore float64 `json:"cvss_score"`

	// Links to advisories
	References []string `json:"references"`
}

// BaseScanner provides common functionality for scanners
type BaseScanner struct {
	config   *config.Config
	cacheDir string
}

// NewBaseScanner creates a new base scanner
func NewBaseScanner(cfg *config.Config) BaseScanner {
	return BaseScanner{
		config:   cfg,
		cacheDir: cfg.CacheDir,
	}
}

// SeverityOrder for sorting
var SeverityOrder = map[string]int{
	"CRITICAL": 0,
	"HIGH":     1,
	"MEDIUM":   2,
	"LOW":      3,
	"UNKNOWN":  4,
}

// SortBySeverity sorts vulnerabilities by severity
func SortBySeverity(vulns []Vulnerability) {
	for i := 0; i < len(vulns); i++ {
		for j := i + 1; j < len(vulns); j++ {
			if SeverityOrder[vulns[i].Severity] > SeverityOrder[vulns[j].Severity] {
				vulns[i], vulns[j] = vulns[j], vulns[i]
			}
		}
	}
}
