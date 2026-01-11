package authz

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/rtvkiz/docker-sentinel/pkg/interceptor"
)

// Converter converts Docker API requests to DockerCommand format
type Converter struct {
	// SecretPatterns are patterns that indicate a secret environment variable
	SecretPatterns []string
}

// NewConverter creates a new API converter
func NewConverter() *Converter {
	return &Converter{
		SecretPatterns: []string{
			"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
			"ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "AUTH", "JWT",
			"BEARER", "AWS_", "GITHUB_", "STRIPE_", "DATABASE_URL",
			"REDIS_URL", "MONGODB_URI", "POSTGRES_", "MYSQL_",
		},
	}
}

// Convert converts a Docker API request to a DockerCommand
func (c *Converter) Convert(req *AuthZRequest) (*interceptor.DockerCommand, error) {
	// Parse the URI to determine the action
	action, params, err := c.parseRequestURI(req.RequestURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URI: %w", err)
	}

	switch action {
	case "containers/create":
		return c.convertContainerCreate(req)
	case "exec":
		return c.convertExecCreate(req, params["id"])
	case "build":
		return c.convertBuild(req)
	case "images/create":
		return c.convertPull(req)
	case "images/push":
		return c.convertPush(req, params["name"])
	default:
		// Return a minimal command for other operations
		return &interceptor.DockerCommand{
			Action:  action,
			RawArgs: []string{req.RequestMethod, req.RequestURI},
		}, nil
	}
}

// parseRequestURI parses the Docker API URI and extracts action and parameters
func (c *Converter) parseRequestURI(uri string) (string, map[string]string, error) {
	// Parse URL
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return "", nil, err
	}

	path := parsedURL.Path
	params := make(map[string]string)

	// Strip API version prefix (e.g., /v1.43/)
	versionRegex := regexp.MustCompile(`^/v[\d.]+/`)
	path = versionRegex.ReplaceAllString(path, "/")
	path = strings.TrimPrefix(path, "/")

	// Match container create: containers/create
	if path == "containers/create" {
		return "containers/create", params, nil
	}

	// Match exec create: containers/{id}/exec
	execRegex := regexp.MustCompile(`^containers/([^/]+)/exec$`)
	if matches := execRegex.FindStringSubmatch(path); matches != nil {
		params["id"] = matches[1]
		return "exec", params, nil
	}

	// Match build: build
	if path == "build" {
		// Extract query parameters
		for key, values := range parsedURL.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
		return "build", params, nil
	}

	// Match image pull: images/create (with fromImage query param)
	if path == "images/create" {
		for key, values := range parsedURL.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
		return "images/create", params, nil
	}

	// Match image push: images/{name}/push
	pushRegex := regexp.MustCompile(`^images/([^/]+)/push$`)
	if matches := pushRegex.FindStringSubmatch(path); matches != nil {
		params["name"] = matches[1]
		return "images/push", params, nil
	}

	// Return the path as the action for unknown endpoints
	return path, params, nil
}

// convertContainerCreate converts a container create request
func (c *Converter) convertContainerCreate(req *AuthZRequest) (*interceptor.DockerCommand, error) {
	var createReq ContainerCreateRequest
	if len(req.RequestBody) > 0 {
		if err := json.Unmarshal(req.RequestBody, &createReq); err != nil {
			return nil, fmt.Errorf("failed to parse container create request: %w", err)
		}
	}

	// Parse query parameters for container name
	parsedURL, err := url.Parse(req.RequestURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URI: %w", err)
	}
	containerName := parsedURL.Query().Get("name")

	cmd := &interceptor.DockerCommand{
		Action:        "run",
		Image:         createReq.Image,
		User:          createReq.User,
		ContainerName: containerName,
		Command:       createReq.Cmd,
		Environment:   c.parseEnvironment(createReq.Env),
		TTY:           createReq.Tty,
		Interactive:   createReq.OpenStdin,
		BuildArgs:     make(map[string]string),
	}

	if len(createReq.Entrypoint) > 0 {
		cmd.Entrypoint = strings.Join(createReq.Entrypoint, " ")
	}

	// Parse HostConfig
	if createReq.HostConfig != nil {
		hc := createReq.HostConfig
		cmd.Privileged = hc.Privileged
		cmd.NetworkMode = hc.NetworkMode
		cmd.PIDMode = hc.PidMode
		cmd.IPCMode = hc.IpcMode
		cmd.UTSMode = hc.UTSMode
		cmd.ReadOnlyRootfs = hc.ReadonlyRootfs
		cmd.Remove = hc.AutoRemove

		// Parse capabilities
		cmd.Capabilities = interceptor.CapabilityConfig{
			Add:  hc.CapAdd,
			Drop: hc.CapDrop,
		}

		// Parse security options
		cmd.SecurityOpts = c.parseSecurityOpts(hc.SecurityOpt)

		// Parse bind mounts
		cmd.Volumes = c.parseBinds(hc.Binds)

		// Parse Mounts (newer format)
		cmd.Volumes = append(cmd.Volumes, c.parseMounts(hc.Mounts)...)

		// Parse port bindings
		cmd.Ports = c.parsePortBindings(hc.PortBindings)

		// Parse resources
		cmd.Resources = c.parseResources(hc.Resources)
	}

	return cmd, nil
}

// convertExecCreate converts an exec create request
func (c *Converter) convertExecCreate(req *AuthZRequest, containerID string) (*interceptor.DockerCommand, error) {
	var execReq ExecCreateRequest
	if len(req.RequestBody) > 0 {
		if err := json.Unmarshal(req.RequestBody, &execReq); err != nil {
			return nil, fmt.Errorf("failed to parse exec create request: %w", err)
		}
	}

	return &interceptor.DockerCommand{
		Action:        "exec",
		ContainerName: containerID,
		Command:       execReq.Cmd,
		User:          execReq.User,
		Privileged:    execReq.Privileged,
		Interactive:   execReq.AttachStdin,
		TTY:           execReq.Tty,
		Environment:   c.parseEnvironment(execReq.Env),
	}, nil
}

// convertBuild converts a build request
func (c *Converter) convertBuild(req *AuthZRequest) (*interceptor.DockerCommand, error) {
	parsedURL, err := url.Parse(req.RequestURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URI: %w", err)
	}
	query := parsedURL.Query()

	cmd := &interceptor.DockerCommand{
		Action:       "build",
		BuildContext: ".",
		BuildArgs:    make(map[string]string),
	}

	// Extract tag (image name)
	if t := query.Get("t"); t != "" {
		cmd.Image = t
	}

	// Extract Dockerfile path
	if dockerfile := query.Get("dockerfile"); dockerfile != "" {
		cmd.Dockerfile = dockerfile
	}

	// Extract build args
	for _, arg := range query["buildargs"] {
		var buildArgs map[string]string
		if err := json.Unmarshal([]byte(arg), &buildArgs); err == nil {
			for k, v := range buildArgs {
				cmd.BuildArgs[k] = v
			}
		}
	}

	// Extract remote context
	if remote := query.Get("remote"); remote != "" {
		cmd.BuildContext = remote
	}

	return cmd, nil
}

// convertPull converts an image pull request
func (c *Converter) convertPull(req *AuthZRequest) (*interceptor.DockerCommand, error) {
	parsedURL, err := url.Parse(req.RequestURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URI: %w", err)
	}
	query := parsedURL.Query()

	image := query.Get("fromImage")
	tag := query.Get("tag")

	if tag != "" && !strings.Contains(image, ":") {
		image = image + ":" + tag
	}

	return &interceptor.DockerCommand{
		Action: "pull",
		Image:  image,
	}, nil
}

// convertPush converts an image push request
func (c *Converter) convertPush(req *AuthZRequest, imageName string) (*interceptor.DockerCommand, error) {
	// URL decode the image name
	decodedName, err := url.PathUnescape(imageName)
	if err != nil {
		decodedName = imageName
	}

	parsedURL, err := url.Parse(req.RequestURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URI: %w", err)
	}
	tag := parsedURL.Query().Get("tag")

	image := decodedName
	if tag != "" && !strings.Contains(image, ":") {
		image = image + ":" + tag
	}

	return &interceptor.DockerCommand{
		Action: "push",
		Image:  image,
	}, nil
}

// parseEnvironment parses environment variables from Docker API format
func (c *Converter) parseEnvironment(env []string) []interceptor.EnvVar {
	var result []interceptor.EnvVar

	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 0 {
			continue
		}

		ev := interceptor.EnvVar{
			Key: parts[0],
		}
		if len(parts) > 1 {
			ev.Value = parts[1]
		}

		// Check if this looks like a secret
		ev.IsSecret = c.isSecretEnvVar(parts[0])

		result = append(result, ev)
	}

	return result
}

// isSecretEnvVar checks if an environment variable name looks like a secret
func (c *Converter) isSecretEnvVar(name string) bool {
	upperName := strings.ToUpper(name)
	for _, pattern := range c.SecretPatterns {
		if strings.Contains(upperName, pattern) {
			return true
		}
	}
	return false
}

// parseSecurityOpts parses security options
func (c *Converter) parseSecurityOpts(opts []string) []interceptor.SecurityOption {
	var result []interceptor.SecurityOption

	for _, opt := range opts {
		parts := strings.SplitN(opt, "=", 2)
		so := interceptor.SecurityOption{
			Type: parts[0],
		}
		if len(parts) > 1 {
			so.Value = parts[1]
		}

		// Handle special cases
		if opt == "no-new-privileges" || opt == "no-new-privileges:true" {
			so.Type = "no-new-privileges"
			so.Value = "true"
		}

		result = append(result, so)
	}

	return result
}

// parseBinds parses bind mount strings (host:container:opts format)
func (c *Converter) parseBinds(binds []string) []interceptor.VolumeMount {
	var result []interceptor.VolumeMount

	for _, bind := range binds {
		parts := strings.Split(bind, ":")

		vm := interceptor.VolumeMount{
			Type: interceptor.MountTypeBind,
		}

		switch len(parts) {
		case 1:
			// Just container path - anonymous volume
			vm.Type = interceptor.MountTypeVolume
			vm.Destination = parts[0]
		case 2:
			// host:container or container:opts
			if strings.HasPrefix(parts[0], "/") || strings.HasPrefix(parts[0], "~") {
				vm.Source = parts[0]
				vm.Destination = parts[1]
			} else {
				// Named volume
				vm.Type = interceptor.MountTypeVolume
				vm.Source = parts[0]
				vm.Destination = parts[1]
			}
		case 3:
			// host:container:opts
			vm.Source = parts[0]
			vm.Destination = parts[1]
			opts := parts[2]
			if strings.Contains(opts, "ro") {
				vm.ReadOnly = true
			}
			// Extract propagation mode
			for _, prop := range []string{"rprivate", "private", "rshared", "shared", "rslave", "slave"} {
				if strings.Contains(opts, prop) {
					vm.Propagation = prop
					break
				}
			}
		}

		result = append(result, vm)
	}

	return result
}

// parseMounts parses Mount structures (newer format)
func (c *Converter) parseMounts(mounts []Mount) []interceptor.VolumeMount {
	var result []interceptor.VolumeMount

	for _, m := range mounts {
		vm := interceptor.VolumeMount{
			Source:      m.Source,
			Destination: m.Target,
			ReadOnly:    m.ReadOnly,
		}

		switch m.Type {
		case "bind":
			vm.Type = interceptor.MountTypeBind
			if m.BindOptions != nil {
				vm.Propagation = m.BindOptions.Propagation
			}
		case "volume":
			vm.Type = interceptor.MountTypeVolume
		case "tmpfs":
			vm.Type = interceptor.MountTypeTmpfs
		default:
			vm.Type = interceptor.MountTypeBind
		}

		result = append(result, vm)
	}

	return result
}

// parsePortBindings parses port bindings
func (c *Converter) parsePortBindings(bindings map[string][]PortBinding) []interceptor.PortMapping {
	var result []interceptor.PortMapping

	for containerPort, hostBindings := range bindings {
		// Parse container port (e.g., "80/tcp")
		parts := strings.Split(containerPort, "/")
		port := parts[0]
		protocol := "tcp"
		if len(parts) > 1 {
			protocol = parts[1]
		}

		for _, hb := range hostBindings {
			result = append(result, interceptor.PortMapping{
				HostIP:        hb.HostIP,
				HostPort:      hb.HostPort,
				ContainerPort: port,
				Protocol:      protocol,
			})
		}
	}

	return result
}

// parseResources parses resource constraints
func (c *Converter) parseResources(res Resources) interceptor.ResourceLimits {
	rl := interceptor.ResourceLimits{
		PIDs: res.PidsLimit,
	}

	// Convert memory to human-readable format
	if res.Memory > 0 {
		rl.Memory = formatBytes(res.Memory)
	}
	if res.MemorySwap > 0 {
		rl.MemorySwap = formatBytes(res.MemorySwap)
	}

	// Convert NanoCPUs to CPU count
	if res.NanoCPUs > 0 {
		cpus := float64(res.NanoCPUs) / 1e9
		rl.CPUs = fmt.Sprintf("%.2f", cpus)
	}

	return rl
}

// formatBytes formats bytes to a human-readable string
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%dg", bytes/GB)
	case bytes >= MB:
		return fmt.Sprintf("%dm", bytes/MB)
	case bytes >= KB:
		return fmt.Sprintf("%dk", bytes/KB)
	default:
		return fmt.Sprintf("%d", bytes)
	}
}

// IsSecurityRelevant checks if a request is security-relevant and needs evaluation
func (c *Converter) IsSecurityRelevant(req *AuthZRequest) bool {
	action, _, err := c.parseRequestURI(req.RequestURI)
	if err != nil {
		// Treat unparseable requests as non-security-relevant
		return false
	}

	// These actions need security evaluation
	securityRelevantActions := map[string]bool{
		"containers/create": true,
		"exec":              true,
		"build":             true,
		"images/create":     true,
		"images/push":       true,
	}

	return securityRelevantActions[action]
}
