package policy

// Policy represents a complete security policy configuration
type Policy struct {
	// Metadata
	Version     string `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Author      string `yaml:"author,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`

	// Operational mode: enforce, warn, audit
	Mode string `yaml:"mode,omitempty"`

	// Global settings
	Settings Settings `yaml:"settings"`

	// Rules configuration
	Rules RulesConfig `yaml:"rules"`

	// Custom rules defined in this policy
	CustomRules []CustomRule `yaml:"custom_rules,omitempty"`

	// OPA/Rego policies
	Rego []RegoPolicy `yaml:"rego,omitempty"`
}

// Settings contains global policy settings
type Settings struct {
	// Maximum allowed risk score (0-100)
	MaxRiskScore int `yaml:"max_risk_score"`

	// Whether to require image scanning before run
	RequireImageScan bool `yaml:"require_image_scan"`

	// Image scanning configuration
	ImageScanning ImageScanSettings `yaml:"image_scanning,omitempty"`

	// Secret scanning configuration
	SecretScanning SecretScanSettings `yaml:"secret_scanning,omitempty"`
}

// ImageScanSettings configures image scanning behavior
type ImageScanSettings struct {
	Enabled       bool     `yaml:"enabled"`
	Scanners      []string `yaml:"scanners"`
	MaxCritical   int      `yaml:"max_critical"`
	MaxHigh       int      `yaml:"max_high"`
	MaxMedium     int      `yaml:"max_medium,omitempty"`
	CacheDuration string   `yaml:"cache_duration"`
}

// SecretScanSettings configures secret scanning behavior
type SecretScanSettings struct {
	// Enable secret scanning
	Enabled bool `yaml:"enabled"`

	// Scanner to use (currently only trufflehog supported)
	Scanner string `yaml:"scanner"`

	// Block if any verified secrets are found
	BlockOnVerified bool `yaml:"block_on_verified"`

	// Maximum allowed secrets by severity (0 = block on any)
	MaxCritical int `yaml:"max_critical"`
	MaxHigh     int `yaml:"max_high"`
	MaxMedium   int `yaml:"max_medium,omitempty"`

	// Score impact for findings
	VerifiedSecretScore   int `yaml:"verified_secret_score,omitempty"`
	CriticalSecretScore   int `yaml:"critical_secret_score,omitempty"`
	HighSecretScore       int `yaml:"high_secret_score,omitempty"`

	// Detectors to ignore (e.g., "Generic", "Base64")
	IgnoreDetectors []string `yaml:"ignore_detectors,omitempty"`

	// Files/paths to exclude from scanning
	ExcludePaths []string `yaml:"exclude_paths,omitempty"`
}

// RulesConfig contains all rule configurations
type RulesConfig struct {
	// Privileged mode
	Privileged RuleAction `yaml:"privileged"`

	// Host namespaces
	HostNamespaces HostNamespaceRules `yaml:"host_namespaces"`

	// Capabilities
	Capabilities CapabilityRules `yaml:"capabilities"`

	// Volume mounts
	Mounts MountRules `yaml:"mounts"`

	// Security options
	SecurityOptions SecurityOptionRules `yaml:"security_options"`

	// Container configuration
	Container ContainerRules `yaml:"container"`

	// Image/registry rules
	Images ImageRules `yaml:"images"`

	// Network rules
	Network NetworkRules `yaml:"network"`

	// Environment variables
	Environment EnvironmentRules `yaml:"environment"`
}

// RuleAction defines what action to take when a rule is triggered
type RuleAction struct {
	// Action: allow, warn, block
	Action string `yaml:"action"`
	// Custom message
	Message string `yaml:"message,omitempty"`
	// Exceptions - conditions where this rule doesn't apply
	Exceptions []Exception `yaml:"exceptions,omitempty"`
}

// Exception defines when a rule should be bypassed
type Exception struct {
	// Match by image pattern
	Images []string `yaml:"images,omitempty"`
	// Match by container name pattern
	Names []string `yaml:"names,omitempty"`
	// Match by label
	Labels map[string]string `yaml:"labels,omitempty"`
	// Reason for exception
	Reason string `yaml:"reason,omitempty"`
}

// HostNamespaceRules configures host namespace rules
type HostNamespaceRules struct {
	Network RuleAction `yaml:"network"`
	PID     RuleAction `yaml:"pid"`
	IPC     RuleAction `yaml:"ipc"`
	UTS     RuleAction `yaml:"uts"`
}

// CapabilityRules configures capability rules
type CapabilityRules struct {
	// Default action for capabilities not in allow/block lists
	DefaultAction string `yaml:"default_action"`
	// Blocked capabilities
	Blocked []CapabilityRule `yaml:"blocked"`
	// Allowed capabilities (overrides blocked)
	Allowed []CapabilityRule `yaml:"allowed,omitempty"`
	// Require dropping all capabilities
	RequireDropAll bool `yaml:"require_drop_all,omitempty"`
}

// CapabilityRule defines a capability rule
type CapabilityRule struct {
	Name    string `yaml:"name"`
	Action  string `yaml:"action,omitempty"`
	Message string `yaml:"message,omitempty"`
}

// MountRules configures volume mount rules
type MountRules struct {
	// Blocked paths - always denied
	Blocked []MountPath `yaml:"blocked"`
	// Warned paths - allowed with warning
	Warned []MountPath `yaml:"warned,omitempty"`
	// Allowed paths - always allowed (overrides blocked/warned)
	Allowed []MountPath `yaml:"allowed,omitempty"`
	// Block all bind mounts
	BlockBindMounts bool `yaml:"block_bind_mounts,omitempty"`
	// Require read-only mounts
	RequireReadOnly bool `yaml:"require_read_only,omitempty"`
}

// MountPath defines a mount path rule
type MountPath struct {
	Path    string `yaml:"path"`
	Action  string `yaml:"action,omitempty"`
	Message string `yaml:"message,omitempty"`
	// Allow if read-only
	AllowReadOnly bool `yaml:"allow_read_only,omitempty"`
}

// SecurityOptionRules configures security option requirements
type SecurityOptionRules struct {
	// Require seccomp profile
	RequireSeccomp bool `yaml:"require_seccomp"`
	// Allowed seccomp profiles (empty = any)
	AllowedSeccompProfiles []string `yaml:"allowed_seccomp_profiles,omitempty"`
	// Require AppArmor profile
	RequireApparmor bool `yaml:"require_apparmor"`
	// Allowed AppArmor profiles (empty = any)
	AllowedApparmorProfiles []string `yaml:"allowed_apparmor_profiles,omitempty"`
	// Require no-new-privileges
	RequireNoNewPrivileges bool `yaml:"require_no_new_privileges,omitempty"`
}

// ContainerRules configures container-level rules
type ContainerRules struct {
	// Require non-root user
	RequireNonRoot bool `yaml:"require_non_root"`
	// Allowed users (UID or username)
	AllowedUsers []string `yaml:"allowed_users,omitempty"`
	// Blocked users
	BlockedUsers []string `yaml:"blocked_users,omitempty"`
	// Require read-only root filesystem
	RequireReadOnlyRootfs bool `yaml:"require_read_only_rootfs,omitempty"`
	// Require resource limits
	RequireResourceLimits bool `yaml:"require_resource_limits,omitempty"`
	// Maximum memory limit
	MaxMemory string `yaml:"max_memory,omitempty"`
	// Maximum CPU limit
	MaxCPUs string `yaml:"max_cpus,omitempty"`
}

// ImageRules configures image and registry rules
type ImageRules struct {
	// Allowed registries
	AllowedRegistries []string `yaml:"allowed_registries"`
	// Blocked registries
	BlockedRegistries []string `yaml:"blocked_registries,omitempty"`
	// Blocked images (full image names or patterns)
	BlockedImages []string `yaml:"blocked_images,omitempty"`
	// Require image digest
	RequireDigest bool `yaml:"require_digest,omitempty"`
	// Block :latest tag
	BlockLatestTag bool `yaml:"block_latest_tag"`
	// Require signed images
	RequireSigned bool `yaml:"require_signed,omitempty"`
}

// NetworkRules configures network-related rules
type NetworkRules struct {
	// Allowed network modes
	AllowedModes []string `yaml:"allowed_modes,omitempty"`
	// Blocked ports
	BlockedPorts []PortRule `yaml:"blocked_ports,omitempty"`
	// Require specific DNS servers
	RequireDNS []string `yaml:"require_dns,omitempty"`
}

// PortRule defines a port blocking rule
type PortRule struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol,omitempty"`
	Message  string `yaml:"message,omitempty"`
}

// EnvironmentRules configures environment variable rules
type EnvironmentRules struct {
	// Block secrets in environment variables
	BlockSecrets bool `yaml:"block_secrets"`
	// Secret patterns to detect
	SecretPatterns []string `yaml:"secret_patterns,omitempty"`
	// Required environment variables
	Required []string `yaml:"required,omitempty"`
	// Blocked environment variable names
	Blocked []string `yaml:"blocked,omitempty"`
}

// CustomRule allows defining custom rules in YAML
type CustomRule struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Severity    string       `yaml:"severity"`
	Category    string       `yaml:"category"`
	Condition   RuleCondition `yaml:"condition"`
	Message     string       `yaml:"message"`
}

// RuleCondition defines the condition for a custom rule
type RuleCondition struct {
	// Field to check (e.g., "privileged", "image", "volumes")
	Field string `yaml:"field"`
	// Operator: equals, not_equals, contains, not_contains, matches, exists
	Operator string `yaml:"operator"`
	// Value to compare against
	Value interface{} `yaml:"value"`
	// For complex conditions
	And []RuleCondition `yaml:"and,omitempty"`
	Or  []RuleCondition `yaml:"or,omitempty"`
}

// RegoPolicy defines an OPA Rego policy
type RegoPolicy struct {
	Name   string `yaml:"name"`
	// Inline Rego code
	Inline string `yaml:"inline,omitempty"`
	// Path to Rego file
	File   string `yaml:"file,omitempty"`
}

// ActionType constants
const (
	ActionAllow = "allow"
	ActionWarn  = "warn"
	ActionBlock = "block"
)

// Default returns a sensible default policy
func Default() *Policy {
	return &Policy{
		Version:     "1.0",
		Name:        "default",
		Description: "Default Docker Sentinel security policy",
		Mode:        "warn",
		Settings: Settings{
			MaxRiskScore:     50,
			RequireImageScan: false,
			ImageScanning: ImageScanSettings{
				Enabled:       true,
				Scanners:      []string{"trivy"},
				MaxCritical:   0,
				MaxHigh:       5,
				CacheDuration: "24h",
			},
			SecretScanning: SecretScanSettings{
				Enabled:              true,
				Scanner:              "trufflehog",
				BlockOnVerified:      true,
				MaxCritical:          0,
				MaxHigh:              0,
				VerifiedSecretScore:  50,
				CriticalSecretScore:  40,
				HighSecretScore:      25,
			},
		},
		Rules: RulesConfig{
			Privileged: RuleAction{Action: ActionBlock},
			HostNamespaces: HostNamespaceRules{
				Network: RuleAction{Action: ActionBlock},
				PID:     RuleAction{Action: ActionBlock},
				IPC:     RuleAction{Action: ActionWarn},
				UTS:     RuleAction{Action: ActionWarn},
			},
			Capabilities: CapabilityRules{
				DefaultAction: ActionWarn,
				Blocked: []CapabilityRule{
					{Name: "SYS_ADMIN", Message: "Grants most admin capabilities"},
					{Name: "SYS_PTRACE", Message: "Allows process tracing"},
					{Name: "SYS_MODULE", Message: "Allows kernel module loading"},
					{Name: "NET_ADMIN", Message: "Allows network configuration"},
					{Name: "NET_RAW", Message: "Allows raw socket access"},
				},
			},
			Mounts: MountRules{
				Blocked: []MountPath{
					{Path: "/", Message: "Host root filesystem"},
					{Path: "/var/run/docker.sock", Message: "Docker socket"},
					{Path: "/proc", Message: "Process filesystem"},
				},
				Warned: []MountPath{
					{Path: "/etc", Message: "System configuration"},
					{Path: "/sys", Message: "System filesystem"},
					{Path: "/home", Message: "User home directories"},
				},
			},
			SecurityOptions: SecurityOptionRules{
				RequireSeccomp:  false,
				RequireApparmor: false,
			},
			Container: ContainerRules{
				RequireNonRoot:        false,
				RequireResourceLimits: false,
			},
			Images: ImageRules{
				AllowedRegistries: []string{"docker.io", "gcr.io", "ghcr.io", "quay.io"},
				BlockLatestTag:    true,
			},
			Environment: EnvironmentRules{
				BlockSecrets: true,
				SecretPatterns: []string{
					"PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY",
				},
			},
		},
	}
}
