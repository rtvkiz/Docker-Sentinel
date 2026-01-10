package authz

import (
	"time"
)

// Docker Authorization Plugin Protocol Types

// AuthZRequest represents a Docker authorization request from the daemon
type AuthZRequest struct {
	// User is the user identification extracted by the authentication mechanism
	User string `json:"User"`

	// UserAuthNMethod is the authentication method used (e.g., TLS client cert)
	UserAuthNMethod string `json:"UserAuthNMethod"`

	// RequestMethod is the HTTP method (GET, POST, DELETE, etc.)
	RequestMethod string `json:"RequestMethod"`

	// RequestURI is the request URI including API version (e.g., /v1.43/containers/create)
	RequestURI string `json:"RequestURI"`

	// RequestBody is the raw HTTP request body (JSON for most endpoints)
	RequestBody []byte `json:"RequestBody"`

	// RequestHeaders contains the HTTP request headers
	RequestHeaders map[string]string `json:"RequestHeaders"`

	// ResponseStatusCode is the HTTP status code (only in AuthZRes)
	ResponseStatusCode int `json:"ResponseStatusCode,omitempty"`

	// ResponseBody is the raw HTTP response body (only in AuthZRes)
	ResponseBody []byte `json:"ResponseBody,omitempty"`

	// ResponseHeaders contains the HTTP response headers (only in AuthZRes)
	ResponseHeaders map[string]string `json:"ResponseHeaders,omitempty"`
}

// AuthZResponse represents a Docker authorization response to the daemon
type AuthZResponse struct {
	// Allow indicates whether the request is allowed
	Allow bool `json:"Allow"`

	// Msg is a message explaining the authorization decision
	Msg string `json:"Msg,omitempty"`

	// Err contains any error message if the authorization failed
	Err string `json:"Err,omitempty"`
}

// PluginActivation is returned when Docker activates the plugin
type PluginActivation struct {
	// Implements lists the plugin types this plugin implements
	Implements []string `json:"Implements"`
}

// Docker API Request Types

// ContainerCreateRequest represents the JSON body of POST /containers/create
type ContainerCreateRequest struct {
	// Image is the image to use for the container
	Image string `json:"Image"`

	// User is the user inside the container
	User string `json:"User,omitempty"`

	// Hostname is the container hostname
	Hostname string `json:"Hostname,omitempty"`

	// Domainname is the container domain name
	Domainname string `json:"Domainname,omitempty"`

	// Entrypoint overrides the image's default entrypoint
	Entrypoint []string `json:"Entrypoint,omitempty"`

	// Cmd is the command to run in the container
	Cmd []string `json:"Cmd,omitempty"`

	// Env is the list of environment variables
	Env []string `json:"Env,omitempty"`

	// Labels is a map of labels to set on the container
	Labels map[string]string `json:"Labels,omitempty"`

	// WorkingDir is the working directory inside the container
	WorkingDir string `json:"WorkingDir,omitempty"`

	// Tty indicates whether to allocate a TTY
	Tty bool `json:"Tty,omitempty"`

	// OpenStdin indicates whether to open stdin
	OpenStdin bool `json:"OpenStdin,omitempty"`

	// HostConfig contains host-specific configuration
	HostConfig *HostConfig `json:"HostConfig,omitempty"`

	// NetworkingConfig contains networking configuration
	NetworkingConfig *NetworkingConfig `json:"NetworkingConfig,omitempty"`
}

// HostConfig contains container host configuration
type HostConfig struct {
	// Privileged gives the container full access to the host
	Privileged bool `json:"Privileged,omitempty"`

	// Binds is a list of volume bindings (host:container:options)
	Binds []string `json:"Binds,omitempty"`

	// Mounts is a list of mount configurations
	Mounts []Mount `json:"Mounts,omitempty"`

	// CapAdd is a list of capabilities to add
	CapAdd []string `json:"CapAdd,omitempty"`

	// CapDrop is a list of capabilities to drop
	CapDrop []string `json:"CapDrop,omitempty"`

	// NetworkMode is the network mode (bridge, host, none, container:name)
	NetworkMode string `json:"NetworkMode,omitempty"`

	// PidMode is the PID namespace mode (host, container:name)
	PidMode string `json:"PidMode,omitempty"`

	// IpcMode is the IPC namespace mode (host, container:name, private, shareable)
	IpcMode string `json:"IpcMode,omitempty"`

	// UTSMode is the UTS namespace mode (host)
	UTSMode string `json:"UTSMode,omitempty"`

	// UsernsMode is the user namespace mode
	UsernsMode string `json:"UsernsMode,omitempty"`

	// SecurityOpt is a list of security options (seccomp, apparmor, label)
	SecurityOpt []string `json:"SecurityOpt,omitempty"`

	// ReadonlyRootfs makes the root filesystem read-only
	ReadonlyRootfs bool `json:"ReadonlyRootfs,omitempty"`

	// PortBindings contains port mappings
	PortBindings map[string][]PortBinding `json:"PortBindings,omitempty"`

	// PublishAllPorts publishes all exposed ports
	PublishAllPorts bool `json:"PublishAllPorts,omitempty"`

	// AutoRemove removes the container when it exits
	AutoRemove bool `json:"AutoRemove,omitempty"`

	// RestartPolicy contains restart policy configuration
	RestartPolicy *RestartPolicy `json:"RestartPolicy,omitempty"`

	// Resources contains resource constraints
	Resources

	// Runtime is the OCI runtime to use
	Runtime string `json:"Runtime,omitempty"`

	// Devices is a list of devices to add to the container
	Devices []DeviceMapping `json:"Devices,omitempty"`

	// CgroupParent is the parent cgroup for the container
	CgroupParent string `json:"CgroupParent,omitempty"`

	// GroupAdd is a list of additional groups
	GroupAdd []string `json:"GroupAdd,omitempty"`

	// Init runs an init inside the container
	Init *bool `json:"Init,omitempty"`

	// ShmSize is the size of /dev/shm in bytes
	ShmSize int64 `json:"ShmSize,omitempty"`

	// Sysctls sets sysctl options
	Sysctls map[string]string `json:"Sysctls,omitempty"`
}

// Mount represents a mount configuration
type Mount struct {
	// Type is the mount type (bind, volume, tmpfs, npipe)
	Type string `json:"Type,omitempty"`

	// Source is the source of the mount (host path or volume name)
	Source string `json:"Source,omitempty"`

	// Target is the path inside the container
	Target string `json:"Target,omitempty"`

	// ReadOnly makes the mount read-only
	ReadOnly bool `json:"ReadOnly,omitempty"`

	// BindOptions contains bind-specific options
	BindOptions *BindOptions `json:"BindOptions,omitempty"`

	// VolumeOptions contains volume-specific options
	VolumeOptions *VolumeOptions `json:"VolumeOptions,omitempty"`

	// TmpfsOptions contains tmpfs-specific options
	TmpfsOptions *TmpfsOptions `json:"TmpfsOptions,omitempty"`
}

// BindOptions contains options for bind mounts
type BindOptions struct {
	// Propagation is the mount propagation mode
	Propagation string `json:"Propagation,omitempty"`

	// NonRecursive disables recursive bind mount
	NonRecursive bool `json:"NonRecursive,omitempty"`
}

// VolumeOptions contains options for volume mounts
type VolumeOptions struct {
	// NoCopy disables copying data from container path
	NoCopy bool `json:"NoCopy,omitempty"`

	// Labels to set on the volume
	Labels map[string]string `json:"Labels,omitempty"`

	// DriverConfig contains volume driver configuration
	DriverConfig *DriverConfig `json:"DriverConfig,omitempty"`
}

// TmpfsOptions contains options for tmpfs mounts
type TmpfsOptions struct {
	// SizeBytes is the size of the tmpfs in bytes
	SizeBytes int64 `json:"SizeBytes,omitempty"`

	// Mode is the file mode of the tmpfs
	Mode uint32 `json:"Mode,omitempty"`
}

// DriverConfig contains volume driver configuration
type DriverConfig struct {
	// Name is the driver name
	Name string `json:"Name,omitempty"`

	// Options are driver-specific options
	Options map[string]string `json:"Options,omitempty"`
}

// PortBinding represents a port binding
type PortBinding struct {
	// HostIP is the host IP to bind to
	HostIP string `json:"HostIp,omitempty"`

	// HostPort is the host port to bind to
	HostPort string `json:"HostPort,omitempty"`
}

// RestartPolicy contains restart policy configuration
type RestartPolicy struct {
	// Name is the restart policy name (no, on-failure, always, unless-stopped)
	Name string `json:"Name,omitempty"`

	// MaximumRetryCount is the maximum number of retries for on-failure
	MaximumRetryCount int `json:"MaximumRetryCount,omitempty"`
}

// Resources contains resource constraints
type Resources struct {
	// Memory is the memory limit in bytes
	Memory int64 `json:"Memory,omitempty"`

	// MemorySwap is the memory+swap limit in bytes
	MemorySwap int64 `json:"MemorySwap,omitempty"`

	// MemoryReservation is the soft memory limit in bytes
	MemoryReservation int64 `json:"MemoryReservation,omitempty"`

	// NanoCPUs is the CPU limit in 10^-9 CPUs
	NanoCPUs int64 `json:"NanoCpus,omitempty"`

	// CPUShares is the relative CPU weight
	CPUShares int64 `json:"CpuShares,omitempty"`

	// CPUPeriod is the CPU CFS period in microseconds
	CPUPeriod int64 `json:"CpuPeriod,omitempty"`

	// CPUQuota is the CPU CFS quota in microseconds
	CPUQuota int64 `json:"CpuQuota,omitempty"`

	// CpusetCpus is the CPUs to use
	CpusetCpus string `json:"CpusetCpus,omitempty"`

	// CpusetMems is the memory nodes to use
	CpusetMems string `json:"CpusetMems,omitempty"`

	// PidsLimit is the maximum number of PIDs
	PidsLimit int64 `json:"PidsLimit,omitempty"`

	// Ulimits is a list of ulimits
	Ulimits []Ulimit `json:"Ulimits,omitempty"`
}

// Ulimit represents a ulimit
type Ulimit struct {
	// Name is the ulimit name
	Name string `json:"Name,omitempty"`

	// Soft is the soft limit
	Soft int64 `json:"Soft,omitempty"`

	// Hard is the hard limit
	Hard int64 `json:"Hard,omitempty"`
}

// DeviceMapping represents a device mapping
type DeviceMapping struct {
	// PathOnHost is the device path on the host
	PathOnHost string `json:"PathOnHost,omitempty"`

	// PathInContainer is the device path in the container
	PathInContainer string `json:"PathInContainer,omitempty"`

	// CgroupPermissions are the cgroup permissions
	CgroupPermissions string `json:"CgroupPermissions,omitempty"`
}

// NetworkingConfig contains networking configuration
type NetworkingConfig struct {
	// EndpointsConfig maps network names to endpoint configurations
	EndpointsConfig map[string]*EndpointConfig `json:"EndpointsConfig,omitempty"`
}

// EndpointConfig contains network endpoint configuration
type EndpointConfig struct {
	// IPAMConfig contains IPAM configuration
	IPAMConfig *IPAMConfig `json:"IPAMConfig,omitempty"`

	// Aliases is a list of network aliases
	Aliases []string `json:"Aliases,omitempty"`

	// NetworkID is the network ID
	NetworkID string `json:"NetworkID,omitempty"`

	// EndpointID is the endpoint ID
	EndpointID string `json:"EndpointID,omitempty"`

	// Gateway is the gateway address
	Gateway string `json:"Gateway,omitempty"`

	// IPAddress is the IP address
	IPAddress string `json:"IPAddress,omitempty"`

	// IPPrefixLen is the IP prefix length
	IPPrefixLen int `json:"IPPrefixLen,omitempty"`

	// MacAddress is the MAC address
	MacAddress string `json:"MacAddress,omitempty"`
}

// IPAMConfig contains IPAM configuration
type IPAMConfig struct {
	// IPv4Address is the IPv4 address
	IPv4Address string `json:"IPv4Address,omitempty"`

	// IPv6Address is the IPv6 address
	IPv6Address string `json:"IPv6Address,omitempty"`

	// LinkLocalIPs is a list of link-local IPs
	LinkLocalIPs []string `json:"LinkLocalIPs,omitempty"`
}

// ExecCreateRequest represents the JSON body of POST /containers/{id}/exec
type ExecCreateRequest struct {
	// Cmd is the command to execute
	Cmd []string `json:"Cmd,omitempty"`

	// User is the user to run the command as
	User string `json:"User,omitempty"`

	// Privileged runs the exec with extended privileges
	Privileged bool `json:"Privileged,omitempty"`

	// AttachStdin attaches stdin
	AttachStdin bool `json:"AttachStdin,omitempty"`

	// AttachStdout attaches stdout
	AttachStdout bool `json:"AttachStdout,omitempty"`

	// AttachStderr attaches stderr
	AttachStderr bool `json:"AttachStderr,omitempty"`

	// Tty allocates a TTY
	Tty bool `json:"Tty,omitempty"`

	// Env is a list of environment variables
	Env []string `json:"Env,omitempty"`

	// WorkingDir is the working directory
	WorkingDir string `json:"WorkingDir,omitempty"`

	// DetachKeys overrides the detach key sequence
	DetachKeys string `json:"DetachKeys,omitempty"`
}

// Plugin Configuration Types

// PluginConfig holds plugin configuration
type PluginConfig struct {
	// SocketPath is the path to the Unix socket
	SocketPath string `json:"socket_path"`

	// PolicyName is the active policy name
	PolicyName string `json:"policy_name"`

	// PoliciesDir is the path to the policies directory
	PoliciesDir string `json:"policies_dir"`

	// FailClosed denies requests if evaluation fails (default: true)
	FailClosed bool `json:"fail_closed"`

	// GracePeriod is the shutdown grace period
	GracePeriod time.Duration `json:"grace_period"`

	// PIDFile is the path to the PID file
	PIDFile string `json:"pid_file"`

	// LogLevel is the logging level
	LogLevel string `json:"log_level"`

	// HotReload enables automatic policy reload on file changes
	HotReload bool `json:"hot_reload"`

	// HotReloadDebounce is the debounce duration for hot reload
	HotReloadDebounce time.Duration `json:"hot_reload_debounce"`
}

// DefaultPluginConfig returns a default plugin configuration
func DefaultPluginConfig() *PluginConfig {
	return &PluginConfig{
		SocketPath:        "/run/docker/plugins/sentinel.sock",
		PolicyName:        "",
		PoliciesDir:       "",
		FailClosed:        true,
		GracePeriod:       30 * time.Second,
		PIDFile:           "/var/run/sentinel-authz.pid",
		LogLevel:          "info",
		HotReload:         true,
		HotReloadDebounce: 500 * time.Millisecond,
	}
}

// Constants for Docker API endpoints
const (
	// ContainersCreate is the endpoint for creating containers
	ContainersCreate = "/containers/create"

	// ContainersExec is the endpoint pattern for creating exec instances
	ContainersExec = "/containers/{id}/exec"

	// ImagesBuild is the endpoint for building images
	ImagesBuild = "/build"

	// ImagesCreate is the endpoint for pulling images
	ImagesCreate = "/images/create"

	// ImagesPush is the endpoint pattern for pushing images
	ImagesPush = "/images/{name}/push"
)

// Constants for plugin protocol
const (
	// AuthZApiRequest is the URL for daemon request authorization
	AuthZApiRequest = "AuthZPlugin.AuthZReq"

	// AuthZApiResponse is the URL for daemon response authorization
	AuthZApiResponse = "AuthZPlugin.AuthZRes"

	// AuthZApiImplements is the name of the interface AuthZ plugins implement
	AuthZApiImplements = "authz"
)
