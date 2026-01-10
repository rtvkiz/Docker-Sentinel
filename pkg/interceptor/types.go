package interceptor

// DockerCommand represents a parsed Docker command
type DockerCommand struct {
	// Raw command string
	RawArgs []string

	// Docker action (run, exec, build, pull, push, etc.)
	Action string

	// Image reference (for run, pull, build)
	Image string

	// Container name (--name flag)
	ContainerName string

	// Security-related flags
	Privileged     bool
	User           string
	NetworkMode    string
	PIDMode        string
	IPCMode        string
	UTSMode        string
	Capabilities   CapabilityConfig
	SecurityOpts   []SecurityOption
	ReadOnlyRootfs bool
	NoNewPrivs     bool

	// Volume mounts
	Volumes []VolumeMount

	// Port mappings
	Ports []PortMapping

	// Environment variables
	Environment []EnvVar

	// Resource limits
	Resources ResourceLimits

	// Build-specific options
	BuildContext string
	Dockerfile   string
	BuildArgs    map[string]string

	// Additional flags
	Interactive bool
	TTY         bool
	Detach      bool
	Remove      bool
	Entrypoint  string
	Command     []string
}

// CapabilityConfig holds capability add/drop configuration
type CapabilityConfig struct {
	Add  []string
	Drop []string
}

// VolumeMount represents a volume/bind mount
type VolumeMount struct {
	Type        MountType // bind, volume, tmpfs
	Source      string    // Host path or volume name
	Destination string    // Container path
	ReadOnly    bool
	Propagation string // rprivate, private, rshared, shared, rslave, slave
}

// MountType represents the type of mount
type MountType string

const (
	MountTypeBind   MountType = "bind"
	MountTypeVolume MountType = "volume"
	MountTypeTmpfs  MountType = "tmpfs"
)

// PortMapping represents a port mapping
type PortMapping struct {
	HostIP        string
	HostPort      string
	ContainerPort string
	Protocol      string // tcp, udp
}

// EnvVar represents an environment variable
type EnvVar struct {
	Key   string
	Value string
	// IsSecret indicates if this might be a secret (based on key name)
	IsSecret bool
}

// SecurityOption represents a security option
type SecurityOption struct {
	Type  string // seccomp, apparmor, label, no-new-privileges
	Value string
}

// ResourceLimits holds container resource limits
type ResourceLimits struct {
	CPUs       string
	Memory     string
	MemorySwap string
	PIDs       int64
}

// Common dangerous patterns
var (
	// Capabilities that are particularly dangerous
	DangerousCapabilities = map[string]string{
		"SYS_ADMIN":    "Grants most administrative capabilities, can lead to container escape",
		"SYS_PTRACE":   "Allows process tracing, can be used to escape containers",
		"SYS_MODULE":   "Allows loading kernel modules",
		"SYS_RAWIO":    "Allows raw I/O port access",
		"SYS_BOOT":     "Allows rebooting the system",
		"NET_ADMIN":    "Allows network administration",
		"NET_RAW":      "Allows use of RAW and PACKET sockets",
		"DAC_OVERRIDE": "Bypasses file permission checks",
		"SETUID":       "Allows changing UID",
		"SETGID":       "Allows changing GID",
		"MAC_ADMIN":    "Allows MAC configuration",
		"MAC_OVERRIDE": "Bypasses MAC policy",
		"AUDIT_WRITE":  "Allows writing to audit log",
		"AUDIT_CONTROL": "Enables audit control",
	}

	// Sensitive host paths that should be flagged
	SensitivePaths = map[string]string{
		"/":                      "Host root filesystem - complete host access",
		"/etc":                   "System configuration files",
		"/var/run/docker.sock":   "Docker socket - allows container escape",
		"/proc":                  "Process filesystem - can leak host info",
		"/sys":                   "System filesystem - can modify host",
		"/dev":                   "Device files - raw device access",
		"/root":                  "Root user home directory",
		"/home":                  "User home directories",
		"/boot":                  "Boot files - can modify boot process",
		"/lib/modules":           "Kernel modules",
		"/usr/src":               "Source code directory",
		"/var/log":               "System logs",
		"/etc/passwd":            "User account information",
		"/etc/shadow":            "Password hashes",
		"/etc/sudoers":           "Sudo configuration",
		"/etc/ssh":               "SSH configuration",
		"~/.ssh":                 "SSH keys",
		"~/.aws":                 "AWS credentials",
		"~/.kube":                "Kubernetes config",
		"~/.docker":              "Docker config",
	}

	// Environment variable names that might contain secrets
	SecretEnvPatterns = []string{
		"PASSWORD",
		"SECRET",
		"TOKEN",
		"API_KEY",
		"APIKEY",
		"ACCESS_KEY",
		"PRIVATE_KEY",
		"CREDENTIAL",
		"AUTH",
		"JWT",
		"BEARER",
		"AWS_",
		"GITHUB_",
		"STRIPE_",
		"DATABASE_URL",
		"REDIS_URL",
		"MONGODB_URI",
		"POSTGRES_",
		"MYSQL_",
	}
)

// IsDangerousCapability checks if a capability is considered dangerous
func IsDangerousCapability(cap string) (bool, string) {
	reason, exists := DangerousCapabilities[cap]
	return exists, reason
}

// IsSensitivePath checks if a path is sensitive
func IsSensitivePath(path string) (bool, string) {
	// Check exact match
	if reason, exists := SensitivePaths[path]; exists {
		return true, reason
	}

	// Check if it's a subdirectory of a sensitive path
	for sensitivePath, reason := range SensitivePaths {
		if len(path) > len(sensitivePath) && path[:len(sensitivePath)+1] == sensitivePath+"/" {
			return true, reason
		}
	}

	return false, ""
}
