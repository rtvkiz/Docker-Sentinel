package interceptor

import (
	"fmt"
	"regexp"
	"strings"
)

// ParseDockerCommand parses docker CLI arguments into a structured DockerCommand
func ParseDockerCommand(args []string) (*DockerCommand, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	// Skip "docker" if it's the first argument
	if args[0] == "docker" {
		args = args[1:]
		if len(args) == 0 {
			return nil, fmt.Errorf("no docker command provided")
		}
	}

	cmd := &DockerCommand{
		RawArgs:     args,
		Capabilities: CapabilityConfig{},
		BuildArgs:   make(map[string]string),
	}

	// First argument is the docker action
	cmd.Action = args[0]

	switch cmd.Action {
	case "run":
		return parseRunCommand(cmd, args[1:])
	case "exec":
		return parseExecCommand(cmd, args[1:])
	case "build":
		return parseBuildCommand(cmd, args[1:])
	case "create":
		return parseRunCommand(cmd, args[1:]) // Similar to run
	case "pull":
		return parsePullCommand(cmd, args[1:])
	case "push":
		return parsePushCommand(cmd, args[1:])
	case "compose":
		return parseComposeCommand(cmd, args[1:])
	default:
		// For other commands, just store the raw args
		return cmd, nil
	}
}

func parseRunCommand(cmd *DockerCommand, args []string) (*DockerCommand, error) {
	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		// Privileged mode
		case arg == "--privileged":
			cmd.Privileged = true
			i++

		// User
		case arg == "-u" || arg == "--user":
			if i+1 < len(args) {
				cmd.User = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--user="):
			cmd.User = strings.TrimPrefix(arg, "--user=")
			i++

		// Network mode
		case arg == "--network" || arg == "--net":
			if i+1 < len(args) {
				cmd.NetworkMode = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--network=") || strings.HasPrefix(arg, "--net="):
			cmd.NetworkMode = strings.TrimPrefix(strings.TrimPrefix(arg, "--network="), "--net=")
			i++

		// PID mode
		case arg == "--pid":
			if i+1 < len(args) {
				cmd.PIDMode = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--pid="):
			cmd.PIDMode = strings.TrimPrefix(arg, "--pid=")
			i++

		// IPC mode
		case arg == "--ipc":
			if i+1 < len(args) {
				cmd.IPCMode = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--ipc="):
			cmd.IPCMode = strings.TrimPrefix(arg, "--ipc=")
			i++

		// UTS mode
		case arg == "--uts":
			if i+1 < len(args) {
				cmd.UTSMode = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--uts="):
			cmd.UTSMode = strings.TrimPrefix(arg, "--uts=")
			i++

		// Capabilities
		case arg == "--cap-add":
			if i+1 < len(args) {
				cmd.Capabilities.Add = append(cmd.Capabilities.Add, strings.ToUpper(args[i+1]))
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--cap-add="):
			cap := strings.TrimPrefix(arg, "--cap-add=")
			cmd.Capabilities.Add = append(cmd.Capabilities.Add, strings.ToUpper(cap))
			i++

		case arg == "--cap-drop":
			if i+1 < len(args) {
				cmd.Capabilities.Drop = append(cmd.Capabilities.Drop, strings.ToUpper(args[i+1]))
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--cap-drop="):
			cap := strings.TrimPrefix(arg, "--cap-drop=")
			cmd.Capabilities.Drop = append(cmd.Capabilities.Drop, strings.ToUpper(cap))
			i++

		// Security options
		case arg == "--security-opt":
			if i+1 < len(args) {
				cmd.SecurityOpts = append(cmd.SecurityOpts, parseSecurityOpt(args[i+1]))
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--security-opt="):
			opt := strings.TrimPrefix(arg, "--security-opt=")
			cmd.SecurityOpts = append(cmd.SecurityOpts, parseSecurityOpt(opt))
			i++

		// Read-only root filesystem
		case arg == "--read-only":
			cmd.ReadOnlyRootfs = true
			i++

		// Volumes
		case arg == "-v" || arg == "--volume":
			if i+1 < len(args) {
				vol, err := parseVolumeShort(args[i+1])
				if err == nil {
					cmd.Volumes = append(cmd.Volumes, vol)
				}
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "-v=") || strings.HasPrefix(arg, "--volume="):
			volStr := strings.TrimPrefix(strings.TrimPrefix(arg, "-v="), "--volume=")
			vol, err := parseVolumeShort(volStr)
			if err == nil {
				cmd.Volumes = append(cmd.Volumes, vol)
			}
			i++

		case arg == "--mount":
			if i+1 < len(args) {
				vol, err := parseMountLong(args[i+1])
				if err == nil {
					cmd.Volumes = append(cmd.Volumes, vol)
				}
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--mount="):
			mountStr := strings.TrimPrefix(arg, "--mount=")
			vol, err := parseMountLong(mountStr)
			if err == nil {
				cmd.Volumes = append(cmd.Volumes, vol)
			}
			i++

		// Ports
		case arg == "-p" || arg == "--publish":
			if i+1 < len(args) {
				port := parsePort(args[i+1])
				cmd.Ports = append(cmd.Ports, port)
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "-p=") || strings.HasPrefix(arg, "--publish="):
			portStr := strings.TrimPrefix(strings.TrimPrefix(arg, "-p="), "--publish=")
			port := parsePort(portStr)
			cmd.Ports = append(cmd.Ports, port)
			i++

		// Environment variables
		case arg == "-e" || arg == "--env":
			if i+1 < len(args) {
				env := parseEnvVar(args[i+1])
				cmd.Environment = append(cmd.Environment, env)
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "-e=") || strings.HasPrefix(arg, "--env="):
			envStr := strings.TrimPrefix(strings.TrimPrefix(arg, "-e="), "--env=")
			env := parseEnvVar(envStr)
			cmd.Environment = append(cmd.Environment, env)
			i++

		// Container name
		case arg == "--name":
			if i+1 < len(args) {
				cmd.ContainerName = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--name="):
			cmd.ContainerName = strings.TrimPrefix(arg, "--name=")
			i++

		// Resource limits
		case arg == "--memory" || arg == "-m":
			if i+1 < len(args) {
				cmd.Resources.Memory = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--memory="):
			cmd.Resources.Memory = strings.TrimPrefix(arg, "--memory=")
			i++

		case arg == "--cpus":
			if i+1 < len(args) {
				cmd.Resources.CPUs = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--cpus="):
			cmd.Resources.CPUs = strings.TrimPrefix(arg, "--cpus=")
			i++

		// Common flags
		case arg == "-i" || arg == "--interactive":
			cmd.Interactive = true
			i++
		case arg == "-t" || arg == "--tty":
			cmd.TTY = true
			i++
		case arg == "-d" || arg == "--detach":
			cmd.Detach = true
			i++
		case arg == "--rm":
			cmd.Remove = true
			i++

		// Entrypoint
		case arg == "--entrypoint":
			if i+1 < len(args) {
				cmd.Entrypoint = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--entrypoint="):
			cmd.Entrypoint = strings.TrimPrefix(arg, "--entrypoint=")
			i++

		// Combined short flags like -it, -dit
		case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2:
			for _, c := range arg[1:] {
				switch c {
				case 'i':
					cmd.Interactive = true
				case 't':
					cmd.TTY = true
				case 'd':
					cmd.Detach = true
				}
			}
			i++

		// Image or command
		default:
			if !strings.HasPrefix(arg, "-") {
				if cmd.Image == "" {
					cmd.Image = arg
				} else {
					cmd.Command = append(cmd.Command, arg)
				}
			}
			i++
		}
	}

	return cmd, nil
}

func parseExecCommand(cmd *DockerCommand, args []string) (*DockerCommand, error) {
	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "-u" || arg == "--user":
			if i+1 < len(args) {
				cmd.User = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--user="):
			cmd.User = strings.TrimPrefix(arg, "--user=")
			i++

		case arg == "--privileged":
			cmd.Privileged = true
			i++

		case arg == "-e" || arg == "--env":
			if i+1 < len(args) {
				env := parseEnvVar(args[i+1])
				cmd.Environment = append(cmd.Environment, env)
				i += 2
			} else {
				i++
			}

		case arg == "-i" || arg == "--interactive":
			cmd.Interactive = true
			i++
		case arg == "-t" || arg == "--tty":
			cmd.TTY = true
			i++

		default:
			if !strings.HasPrefix(arg, "-") {
				if cmd.ContainerName == "" {
					cmd.ContainerName = arg
				} else {
					cmd.Command = append(cmd.Command, arg)
				}
			}
			i++
		}
	}

	return cmd, nil
}

func parseBuildCommand(cmd *DockerCommand, args []string) (*DockerCommand, error) {
	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "-f" || arg == "--file":
			if i+1 < len(args) {
				cmd.Dockerfile = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--file="):
			cmd.Dockerfile = strings.TrimPrefix(arg, "--file=")
			i++

		case arg == "-t" || arg == "--tag":
			if i+1 < len(args) {
				cmd.Image = args[i+1]
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--tag="):
			cmd.Image = strings.TrimPrefix(arg, "--tag=")
			i++

		case arg == "--build-arg":
			if i+1 < len(args) {
				parts := strings.SplitN(args[i+1], "=", 2)
				if len(parts) == 2 {
					cmd.BuildArgs[parts[0]] = parts[1]
				}
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(arg, "--build-arg="):
			buildArg := strings.TrimPrefix(arg, "--build-arg=")
			parts := strings.SplitN(buildArg, "=", 2)
			if len(parts) == 2 {
				cmd.BuildArgs[parts[0]] = parts[1]
			}
			i++

		default:
			if !strings.HasPrefix(arg, "-") {
				cmd.BuildContext = arg
			}
			i++
		}
	}

	return cmd, nil
}

func parsePullCommand(cmd *DockerCommand, args []string) (*DockerCommand, error) {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			cmd.Image = arg
			break
		}
	}
	return cmd, nil
}

func parsePushCommand(cmd *DockerCommand, args []string) (*DockerCommand, error) {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			cmd.Image = arg
			break
		}
	}
	return cmd, nil
}

func parseComposeCommand(cmd *DockerCommand, args []string) (*DockerCommand, error) {
	// Store compose subcommand
	if len(args) > 0 {
		cmd.Command = args
	}
	return cmd, nil
}

func parseVolumeShort(vol string) (VolumeMount, error) {
	mount := VolumeMount{
		Type: MountTypeBind,
	}

	parts := strings.Split(vol, ":")
	switch len(parts) {
	case 1:
		// Anonymous volume
		mount.Destination = parts[0]
		mount.Type = MountTypeVolume
	case 2:
		mount.Source = parts[0]
		mount.Destination = parts[1]
		// Check if source is a path or named volume
		if strings.HasPrefix(parts[0], "/") || strings.HasPrefix(parts[0], "./") || strings.HasPrefix(parts[0], "~") {
			mount.Type = MountTypeBind
		} else {
			mount.Type = MountTypeVolume
		}
	case 3:
		mount.Source = parts[0]
		mount.Destination = parts[1]
		if strings.Contains(parts[2], "ro") {
			mount.ReadOnly = true
		}
		if strings.HasPrefix(parts[0], "/") || strings.HasPrefix(parts[0], "./") || strings.HasPrefix(parts[0], "~") {
			mount.Type = MountTypeBind
		} else {
			mount.Type = MountTypeVolume
		}
	}

	return mount, nil
}

func parseMountLong(mount string) (VolumeMount, error) {
	vol := VolumeMount{}

	pairs := strings.Split(mount, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(kv[0])
		value := kv[1]

		switch key {
		case "type":
			vol.Type = MountType(value)
		case "source", "src":
			vol.Source = value
		case "destination", "dst", "target":
			vol.Destination = value
		case "readonly", "ro":
			vol.ReadOnly = value == "true" || value == "1"
		case "bind-propagation":
			vol.Propagation = value
		}
	}

	return vol, nil
}

func parsePort(port string) PortMapping {
	mapping := PortMapping{
		Protocol: "tcp",
	}

	// Handle protocol suffix
	if strings.HasSuffix(port, "/udp") {
		mapping.Protocol = "udp"
		port = strings.TrimSuffix(port, "/udp")
	} else if strings.HasSuffix(port, "/tcp") {
		port = strings.TrimSuffix(port, "/tcp")
	}

	parts := strings.Split(port, ":")
	switch len(parts) {
	case 1:
		mapping.ContainerPort = parts[0]
	case 2:
		mapping.HostPort = parts[0]
		mapping.ContainerPort = parts[1]
	case 3:
		mapping.HostIP = parts[0]
		mapping.HostPort = parts[1]
		mapping.ContainerPort = parts[2]
	}

	return mapping
}

func parseEnvVar(env string) EnvVar {
	parts := strings.SplitN(env, "=", 2)
	e := EnvVar{
		Key: parts[0],
	}
	if len(parts) == 2 {
		e.Value = parts[1]
	}

	// Check if this might be a secret
	e.IsSecret = isSecretEnvVar(e.Key)

	return e
}

func isSecretEnvVar(key string) bool {
	upperKey := strings.ToUpper(key)
	for _, pattern := range SecretEnvPatterns {
		if strings.Contains(upperKey, pattern) {
			return true
		}
	}
	return false
}

func parseSecurityOpt(opt string) SecurityOption {
	secOpt := SecurityOption{}

	parts := strings.SplitN(opt, "=", 2)
	if len(parts) == 1 {
		parts = strings.SplitN(opt, ":", 2)
	}

	secOpt.Type = parts[0]
	if len(parts) == 2 {
		secOpt.Value = parts[1]
	}

	return secOpt
}

// HasHostNamespace checks if the command uses any host namespaces
func (c *DockerCommand) HasHostNamespace() bool {
	return c.NetworkMode == "host" ||
		c.PIDMode == "host" ||
		c.IPCMode == "host" ||
		c.UTSMode == "host"
}

// HasDangerousCapabilities checks if any dangerous capabilities are added
func (c *DockerCommand) HasDangerousCapabilities() []string {
	var dangerous []string
	for _, cap := range c.Capabilities.Add {
		if _, isDangerous := DangerousCapabilities[cap]; isDangerous {
			dangerous = append(dangerous, cap)
		}
	}
	return dangerous
}

// HasSensitiveMounts checks if any sensitive paths are mounted
func (c *DockerCommand) HasSensitiveMounts() []VolumeMount {
	var sensitive []VolumeMount
	for _, vol := range c.Volumes {
		if vol.Type == MountTypeBind {
			if isSensitive, _ := IsSensitivePath(vol.Source); isSensitive {
				sensitive = append(sensitive, vol)
			}
		}
	}
	return sensitive
}

// HasDisabledSecurity checks if security features are disabled
func (c *DockerCommand) HasDisabledSecurity() bool {
	for _, opt := range c.SecurityOpts {
		if opt.Type == "seccomp" && opt.Value == "unconfined" {
			return true
		}
		if opt.Type == "apparmor" && opt.Value == "unconfined" {
			return true
		}
	}
	return false
}

// GetImageRegistry extracts the registry from the image reference
func (c *DockerCommand) GetImageRegistry() string {
	image := c.Image
	if image == "" {
		return ""
	}

	// Remove tag
	if idx := strings.LastIndex(image, ":"); idx > 0 {
		// Make sure it's not part of a port number
		beforeColon := image[:idx]
		if !strings.Contains(beforeColon, "/") || !isPort(image[idx+1:]) {
			image = beforeColon
		}
	}

	// Remove digest
	if idx := strings.Index(image, "@"); idx > 0 {
		image = image[:idx]
	}

	// Check for registry
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		// Single name like "ubuntu" = official Docker Hub library image
		return "docker.io/library"
	}

	// If first part contains a dot or colon, it's a registry
	if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
		return parts[0]
	}

	// Otherwise it's a docker.io user/repo (e.g., "nginx/nginx" -> "docker.io/nginx")
	return "docker.io/" + parts[0]
}

func isPort(s string) bool {
	matched, _ := regexp.MatchString(`^\d+$`, s)
	return matched
}
