package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the main configuration for Docker Sentinel
type Config struct {
	Version      string `yaml:"version"`
	Mode         Mode   `yaml:"mode"`
	ActivePolicy string `yaml:"active_policy"`

	GlobalSettings GlobalSettings `yaml:"global_settings"`
	ImageScanning  ImageScanning  `yaml:"image_scanning"`
	Notifications  Notifications  `yaml:"notifications"`

	// Runtime paths
	ConfigDir   string `yaml:"-"`
	PoliciesDir string `yaml:"-"`
	CacheDir    string `yaml:"-"`
}

// Mode represents the operational mode of sentinel
type Mode string

const (
	ModeEnforce Mode = "enforce" // Block dangerous commands
	ModeWarn    Mode = "warn"    // Warn but allow
	ModeAudit   Mode = "audit"   // Log everything, allow all
)

// GlobalSettings contains global security settings
type GlobalSettings struct {
	AllowPrivileged    bool `yaml:"allow_privileged"`
	AllowHostNetwork   bool `yaml:"allow_host_network"`
	AllowHostPID       bool `yaml:"allow_host_pid"`
	AllowHostIPC       bool `yaml:"allow_host_ipc"`
	MaxRiskScore       int  `yaml:"max_risk_score"`
	RequireImageScan   bool `yaml:"require_image_scan"`
	RequireNonRoot     bool `yaml:"require_non_root"`
	RequireReadOnlyFS  bool `yaml:"require_read_only_fs"`
}

// ImageScanning contains image scanning configuration
type ImageScanning struct {
	Enabled       bool     `yaml:"enabled"`
	Scanners      []string `yaml:"scanners"`
	MaxCritical   int      `yaml:"max_critical"`
	MaxHigh       int      `yaml:"max_high"`
	CacheDuration string   `yaml:"cache_duration"`
}

// Notifications contains notification settings
type Notifications struct {
	WebhookURL   string   `yaml:"webhook_url"`
	SlackWebhook string   `yaml:"slack_webhook"`
	EmailAlerts  []string `yaml:"email_alerts"`
}

// Policy represents a security policy
type Policy struct {
	Name                string           `yaml:"name"`
	Description         string           `yaml:"description"`
	AllowPrivileged     bool             `yaml:"allow_privileged"`
	AllowHostNetwork    bool             `yaml:"allow_host_network"`
	AllowHostPID        bool             `yaml:"allow_host_pid"`
	AllowHostIPC        bool             `yaml:"allow_host_ipc"`
	MaxRiskScore        int              `yaml:"max_risk_score"`
	RequireImageScan    bool             `yaml:"require_image_scan"`
	BlockedCapabilities []string         `yaml:"blocked_capabilities"`
	AllowedRegistries   []string         `yaml:"allowed_registries"`
	DangerousMounts     []DangerousMount `yaml:"dangerous_mounts"`
	SecurityOptions     SecurityOptions  `yaml:"security_options"`
}

// DangerousMount represents a mount path that should be flagged
type DangerousMount struct {
	Path   string `yaml:"path"`
	Action string `yaml:"action"` // block, warn
}

// SecurityOptions contains security option requirements
type SecurityOptions struct {
	RequireSeccomp     bool `yaml:"require_seccomp"`
	RequireApparmor    bool `yaml:"require_apparmor"`
	AllowNoNewPrivs    bool `yaml:"allow_no_new_privileges"`
}

// Load loads configuration from file
func Load(cfgFile string) (*Config, error) {
	cfg := Default()

	if cfgFile == "" {
		cfgFile = filepath.Join(cfg.ConfigDir, "config.yaml")
	}

	data, err := os.ReadFile(cfgFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			if err := cfg.SaveTo(cfgFile); err != nil {
				return cfg, err
			}
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// getConfigDir returns the configuration directory based on priority:
// 1. SENTINEL_CONFIG_DIR environment variable
// 2. /etc/sentinel (if running as root or if it exists and is readable)
// 3. ~/.sentinel (user fallback)
func getConfigDir() string {
	// 1. Environment variable override (highest priority)
	if envDir := os.Getenv("SENTINEL_CONFIG_DIR"); envDir != "" {
		return envDir
	}

	// 2. System-wide config (preferred for enterprise/daemon use)
	systemDir := "/etc/sentinel"
	if os.Geteuid() == 0 {
		// Running as root - use system directory
		return systemDir
	}

	// Check if system config exists and is readable (non-root user)
	if _, err := os.Stat(systemDir); err == nil {
		return systemDir
	}

	// 3. User home directory fallback
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".sentinel")
}

// Default returns the default configuration
func Default() *Config {
	configDir := getConfigDir()

	return &Config{
		Version:      "1.0",
		Mode:         ModeWarn,
		ActivePolicy: "default",

		GlobalSettings: GlobalSettings{
			AllowPrivileged:   false,
			AllowHostNetwork:  false,
			AllowHostPID:      false,
			AllowHostIPC:      false,
			MaxRiskScore:      50,
			RequireImageScan:  false,
			RequireNonRoot:    false,
			RequireReadOnlyFS: false,
		},

		ImageScanning: ImageScanning{
			Enabled:       true,
			Scanners:      []string{"trivy"},
			MaxCritical:   0,
			MaxHigh:       5,
			CacheDuration: "24h",
		},

		ConfigDir:   configDir,
		PoliciesDir: filepath.Join(configDir, "policies"),
		CacheDir:    filepath.Join(configDir, "cache"),
	}
}

// Save saves the configuration to the default config file
func (c *Config) Save() error {
	if c.ConfigDir == "" {
		c.ConfigDir = getConfigDir()
	}
	return c.SaveTo(filepath.Join(c.ConfigDir, "config.yaml"))
}

// SaveTo saves the configuration to a specific file
func (c *Config) SaveTo(path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// GetActivePolicy returns the currently active policy
func (c *Config) GetActivePolicy() (*Policy, error) {
	policyFile := filepath.Join(c.PoliciesDir, c.ActivePolicy+".yaml")

	data, err := os.ReadFile(policyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return nil, err
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// DefaultPolicy returns the default security policy
func DefaultPolicy() *Policy {
	return &Policy{
		Name:             "default",
		Description:      "Default security policy",
		AllowPrivileged:  false,
		AllowHostNetwork: false,
		AllowHostPID:     false,
		AllowHostIPC:     false,
		MaxRiskScore:     50,
		RequireImageScan: false,
		BlockedCapabilities: []string{
			"SYS_ADMIN",
			"SYS_MODULE",
			"SYS_RAWIO",
			"SYS_PTRACE",
			"NET_ADMIN",
			"NET_RAW",
			"SYS_BOOT",
			"MAC_ADMIN",
			"MAC_OVERRIDE",
		},
		AllowedRegistries: []string{
			"docker.io",
			"gcr.io",
			"ghcr.io",
			"quay.io",
		},
		DangerousMounts: []DangerousMount{
			{Path: "/", Action: "block"},
			{Path: "/var/run/docker.sock", Action: "warn"},
			{Path: "/proc", Action: "block"},
			{Path: "/sys", Action: "warn"},
			{Path: "/etc", Action: "warn"},
			{Path: "/root", Action: "warn"},
			{Path: "/home", Action: "warn"},
		},
		SecurityOptions: SecurityOptions{
			RequireSeccomp:  false,
			RequireApparmor: false,
			AllowNoNewPrivs: true,
		},
	}
}
