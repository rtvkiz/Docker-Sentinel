package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
)

// imageNameRegex validates Docker image names
// Allows: registry/namespace/image:tag or image@digest
// Format: [registry/][namespace/]image[:tag][@digest]
var imageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._/-]*[a-zA-Z0-9])?(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// ValidateImageName validates a Docker image name for security
// Prevents command injection and path traversal attacks
func ValidateImageName(image string) error {
	if image == "" {
		return fmt.Errorf("image name cannot be empty")
	}

	// Max reasonable length for image name
	if len(image) > 512 {
		return fmt.Errorf("image name too long (max 512 characters)")
	}

	// Prevent argument injection (image starting with -)
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("image name cannot start with a dash")
	}

	// Prevent null bytes
	if strings.ContainsRune(image, 0) {
		return fmt.Errorf("image name contains invalid null byte")
	}

	// Prevent shell metacharacters
	shellChars := []string{";", "&", "|", "$", "`", "(", ")", "{", "}", "<", ">", "\\", "\"", "'", "\n", "\r", "\t"}
	for _, char := range shellChars {
		if strings.Contains(image, char) {
			return fmt.Errorf("image name contains invalid character: %q", char)
		}
	}

	// Prevent path traversal
	if strings.Contains(image, "..") {
		return fmt.Errorf("image name contains path traversal sequence")
	}

	// Validate against regex pattern
	if !imageNameRegex.MatchString(image) {
		return fmt.Errorf("image name contains invalid characters or format")
	}

	return nil
}

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
