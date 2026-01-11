package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/rtvkiz/docker-sentinel/pkg/interceptor"
)

// OPA evaluation timeout to prevent DoS via expensive policies
const opaEvalTimeout = 5 * time.Second

// OPAEngine evaluates Rego policies
type OPAEngine struct {
	policies   map[string]*rego.PreparedEvalQuery
	policyDir  string
}

// NewOPAEngine creates a new OPA engine
func NewOPAEngine(policyDir string) *OPAEngine {
	return &OPAEngine{
		policies:  make(map[string]*rego.PreparedEvalQuery),
		policyDir: policyDir,
	}
}

// LoadPolicy loads and compiles a Rego policy
func (o *OPAEngine) LoadPolicy(name, regoCode string) error {
	ctx := context.Background()

	query, err := rego.New(
		rego.Query("data.docker.security"),
		rego.Module(name+".rego", regoCode),
	).PrepareForEval(ctx)

	if err != nil {
		return fmt.Errorf("failed to compile policy %s: %w", name, err)
	}

	o.policies[name] = &query
	return nil
}

// LoadPolicyFile loads a Rego policy from a file
func (o *OPAEngine) LoadPolicyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	name := strings.TrimSuffix(filepath.Base(path), ".rego")
	return o.LoadPolicy(name, string(data))
}

// LoadPoliciesFromDir loads all Rego policies from a directory
func (o *OPAEngine) LoadPoliciesFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if err := o.LoadPolicyFile(path); err != nil {
			return fmt.Errorf("failed to load %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// OPAResult contains the result of OPA policy evaluation
type OPAResult struct {
	Denied   []OPAViolation
	Warnings []OPAViolation
	Allowed  bool
}

// OPAViolation represents a policy violation
type OPAViolation struct {
	Policy  string
	Message string
}

// Evaluate evaluates all loaded policies against a Docker command
func (o *OPAEngine) Evaluate(cmd *interceptor.DockerCommand) (*OPAResult, error) {
	result := &OPAResult{
		Allowed: true,
	}

	// Convert command to input format for OPA
	input := commandToOPAInput(cmd)

	// Use timeout context to prevent DoS via expensive policies
	ctx, cancel := context.WithTimeout(context.Background(), opaEvalTimeout)
	defer cancel()

	for name, query := range o.policies {
		results, err := query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			// Check if timeout was exceeded
			if ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("policy evaluation timed out after %v", opaEvalTimeout)
			}
			return nil, fmt.Errorf("failed to evaluate policy %s: %w", name, err)
		}

		if len(results) == 0 || len(results[0].Expressions) == 0 {
			continue
		}

		// Parse results
		if output, ok := results[0].Expressions[0].Value.(map[string]interface{}); ok {
			// Check for deny rules
			if deny, ok := output["deny"].([]interface{}); ok {
				for _, msg := range deny {
					result.Denied = append(result.Denied, OPAViolation{
						Policy:  name,
						Message: fmt.Sprintf("%v", msg),
					})
					result.Allowed = false
				}
			}

			// Check for warn rules
			if warn, ok := output["warn"].([]interface{}); ok {
				for _, msg := range warn {
					result.Warnings = append(result.Warnings, OPAViolation{
						Policy:  name,
						Message: fmt.Sprintf("%v", msg),
					})
				}
			}
		}
	}

	return result, nil
}

// commandToOPAInput converts a DockerCommand to OPA input format
func commandToOPAInput(cmd *interceptor.DockerCommand) map[string]interface{} {
	// Convert volumes to simpler format
	var volumes []map[string]interface{}
	for _, vol := range cmd.Volumes {
		volumes = append(volumes, map[string]interface{}{
			"source":      vol.Source,
			"destination": vol.Destination,
			"read_only":   vol.ReadOnly,
			"type":        string(vol.Type),
		})
	}

	// Convert environment variables
	var envVars []map[string]interface{}
	for _, env := range cmd.Environment {
		envVars = append(envVars, map[string]interface{}{
			"key":       env.Key,
			"value":     env.Value,
			"is_secret": env.IsSecret,
		})
	}

	// Convert capabilities
	caps := map[string]interface{}{
		"add":  cmd.Capabilities.Add,
		"drop": cmd.Capabilities.Drop,
	}

	// Convert security options
	var secOpts []map[string]interface{}
	for _, opt := range cmd.SecurityOpts {
		secOpts = append(secOpts, map[string]interface{}{
			"type":  opt.Type,
			"value": opt.Value,
		})
	}

	return map[string]interface{}{
		"action":           cmd.Action,
		"image":            cmd.Image,
		"container_name":   cmd.ContainerName,
		"privileged":       cmd.Privileged,
		"user":             cmd.User,
		"network_mode":     cmd.NetworkMode,
		"pid_mode":         cmd.PIDMode,
		"ipc_mode":         cmd.IPCMode,
		"uts_mode":         cmd.UTSMode,
		"capabilities":     caps,
		"security_options": secOpts,
		"read_only_rootfs": cmd.ReadOnlyRootfs,
		"volumes":          volumes,
		"environment":      envVars,
		"resources": map[string]interface{}{
			"memory": cmd.Resources.Memory,
			"cpus":   cmd.Resources.CPUs,
		},
	}
}

// DefaultPolicies returns the built-in Rego policies
func DefaultPolicies() map[string]string {
	return map[string]string{
		"privileged": `
package docker.security

# Deny privileged containers
deny[msg] {
    input.privileged == true
    msg := "Privileged containers are not allowed"
}
`,
		"capabilities": `
package docker.security

# Dangerous capabilities
dangerous_caps := {
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "NET_ADMIN",
    "NET_RAW"
}

deny[msg] {
    cap := input.capabilities.add[_]
    dangerous_caps[cap]
    msg := sprintf("Dangerous capability not allowed: %s", [cap])
}

deny[msg] {
    input.capabilities.add[_] == "ALL"
    msg := "Adding ALL capabilities is not allowed"
}
`,
		"mounts": `
package docker.security

# Sensitive mount paths
sensitive_paths := {
    "/": "host root filesystem",
    "/var/run/docker.sock": "Docker socket",
    "/run/docker.sock": "Docker socket",
    "/proc": "process filesystem",
    "/sys": "system filesystem"
}

deny[msg] {
    vol := input.volumes[_]
    reason := sensitive_paths[vol.source]
    msg := sprintf("Mounting %s is blocked: %s", [vol.source, reason])
}

warn[msg] {
    vol := input.volumes[_]
    startswith(vol.source, "/etc")
    msg := sprintf("Mounting %s may expose sensitive data", [vol.source])
}
`,
		"namespaces": `
package docker.security

deny[msg] {
    input.network_mode == "host"
    msg := "Host network mode is not allowed"
}

deny[msg] {
    input.pid_mode == "host"
    msg := "Host PID namespace is not allowed"
}

deny[msg] {
    input.ipc_mode == "host"
    msg := "Host IPC namespace is not allowed"
}
`,
		"security-options": `
package docker.security

deny[msg] {
    opt := input.security_options[_]
    opt.type == "seccomp"
    opt.value == "unconfined"
    msg := "Seccomp must not be disabled"
}

deny[msg] {
    opt := input.security_options[_]
    opt.type == "apparmor"
    opt.value == "unconfined"
    msg := "AppArmor must not be disabled"
}
`,
		"secrets": `
package docker.security

# Patterns that indicate secrets
secret_patterns := [
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL"
]

warn[msg] {
    env := input.environment[_]
    env.is_secret == true
    env.value != ""
    msg := sprintf("Potential secret in environment variable: %s", [env.key])
}
`,
		"images": `
package docker.security

# Block :latest tag
warn[msg] {
    endswith(input.image, ":latest")
    msg := "Using :latest tag is not recommended"
}

warn[msg] {
    not contains(input.image, ":")
    not contains(input.image, "@")
    msg := "No image tag specified (defaults to :latest)"
}
`,
	}
}

// CreateDefaultRegoFiles creates default Rego policy files
func CreateDefaultRegoFiles(dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	for name, content := range DefaultPolicies() {
		path := filepath.Join(dir, name+".rego")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Use secure file permissions (owner read/write only)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				return err
			}
		}
	}

	return nil
}
