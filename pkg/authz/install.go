package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallConfig holds installation configuration
type InstallConfig struct {
	// DockerConfigPath is the path to daemon.json
	DockerConfigPath string

	// PluginName is the name to register the plugin as
	PluginName string

	// SocketPath is the path to the plugin socket
	SocketPath string

	// SentinelPath is the path to the sentinel binary
	SentinelPath string
}

// DefaultInstallConfig returns a default installation configuration
func DefaultInstallConfig() *InstallConfig {
	sentinelPath, _ := exec.LookPath("sentinel")
	if sentinelPath == "" {
		sentinelPath = "/usr/local/bin/sentinel"
	}

	return &InstallConfig{
		DockerConfigPath: "/etc/docker/daemon.json",
		PluginName:       "sentinel",
		SocketPath:       "/run/docker/plugins/sentinel.sock",
		SentinelPath:     sentinelPath,
	}
}

// Install configures Docker to use the Sentinel authorization plugin
func Install(cfg *InstallConfig) error {
	// Read existing daemon.json
	daemonCfg, err := readDaemonConfig(cfg.DockerConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read daemon.json: %w", err)
	}
	if daemonCfg == nil {
		daemonCfg = make(map[string]interface{})
	}

	// Add authorization plugin
	authzPlugins, _ := daemonCfg["authorization-plugins"].([]interface{})
	if !containsPlugin(authzPlugins, cfg.PluginName) {
		authzPlugins = append(authzPlugins, cfg.PluginName)
		daemonCfg["authorization-plugins"] = authzPlugins
	}

	// Write updated daemon.json
	if err := writeDaemonConfig(cfg.DockerConfigPath, daemonCfg); err != nil {
		return fmt.Errorf("failed to write daemon.json: %w", err)
	}

	// Create plugin spec file
	if err := createPluginSpec(cfg); err != nil {
		return fmt.Errorf("failed to create plugin spec: %w", err)
	}

	return nil
}

// Uninstall removes the Sentinel authorization plugin from Docker configuration
func Uninstall(cfg *InstallConfig) error {
	// Read daemon.json
	daemonCfg, err := readDaemonConfig(cfg.DockerConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to uninstall
		}
		return fmt.Errorf("failed to read daemon.json: %w", err)
	}

	// Remove plugin from authorization-plugins
	authzPlugins, _ := daemonCfg["authorization-plugins"].([]interface{})
	daemonCfg["authorization-plugins"] = removePlugin(authzPlugins, cfg.PluginName)

	// If no authorization plugins left, remove the key
	if plugins, ok := daemonCfg["authorization-plugins"].([]interface{}); ok && len(plugins) == 0 {
		delete(daemonCfg, "authorization-plugins")
	}

	// Write updated daemon.json
	if err := writeDaemonConfig(cfg.DockerConfigPath, daemonCfg); err != nil {
		return fmt.Errorf("failed to write daemon.json: %w", err)
	}

	// Remove plugin spec file
	specPath := filepath.Join("/etc/docker/plugins", cfg.PluginName+".spec")
	os.Remove(specPath)

	return nil
}

// InstallSystemdService installs the systemd service file
func InstallSystemdService(cfg *InstallConfig) error {
	serviceContent := GenerateSystemdService(cfg)

	servicePath := "/etc/systemd/system/docker-sentinel.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	return nil
}

// UninstallSystemdService removes the systemd service file
func UninstallSystemdService() error {
	// Stop and disable service
	exec.Command("systemctl", "stop", "docker-sentinel").Run()
	exec.Command("systemctl", "disable", "docker-sentinel").Run()

	// Remove service file
	os.Remove("/etc/systemd/system/docker-sentinel.service")

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	return nil
}

// GenerateSystemdService generates the systemd service file content
func GenerateSystemdService(cfg *InstallConfig) string {
	return fmt.Sprintf(`[Unit]
Description=Docker Sentinel Authorization Plugin
Documentation=https://github.com/rtvkiz/docker-sentinel
After=network.target
Before=docker.service
Requires=docker.socket

[Service]
Type=simple
ExecStart=%s authz start --foreground --socket %s
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=docker

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/run/docker/plugins /var/lib/sentinel /var/run

# Environment
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
`, cfg.SentinelPath, cfg.SocketPath)
}

// RestartDocker restarts the Docker daemon
func RestartDocker() error {
	cmd := exec.Command("systemctl", "restart", "docker")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart Docker: %w", err)
	}
	return nil
}

// CheckDockerStatus checks if Docker is running
func CheckDockerStatus() (bool, error) {
	cmd := exec.Command("systemctl", "is-active", "docker")
	output, err := cmd.Output()
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(output)) == "active", nil
}

// readDaemonConfig reads the Docker daemon configuration
func readDaemonConfig(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return cfg, nil
}

// writeDaemonConfig writes the Docker daemon configuration
func writeDaemonConfig(path string, cfg map[string]interface{}) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal with indentation for readability
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// createPluginSpec creates the plugin specification file
func createPluginSpec(cfg *InstallConfig) error {
	specDir := "/etc/docker/plugins"
	if err := os.MkdirAll(specDir, 0755); err != nil {
		return err
	}

	specPath := filepath.Join(specDir, cfg.PluginName+".spec")
	specContent := fmt.Sprintf("unix://%s", cfg.SocketPath)

	return os.WriteFile(specPath, []byte(specContent), 0644)
}

// containsPlugin checks if a plugin name is in the list
func containsPlugin(plugins []interface{}, name string) bool {
	for _, p := range plugins {
		if s, ok := p.(string); ok && s == name {
			return true
		}
	}
	return false
}

// removePlugin removes a plugin from the list
func removePlugin(plugins []interface{}, name string) []interface{} {
	var result []interface{}
	for _, p := range plugins {
		if s, ok := p.(string); ok && s != name {
			result = append(result, p)
		}
	}
	return result
}

// IsInstalled checks if the plugin is installed in Docker configuration
func IsInstalled(cfg *InstallConfig) (bool, error) {
	daemonCfg, err := readDaemonConfig(cfg.DockerConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	authzPlugins, _ := daemonCfg["authorization-plugins"].([]interface{})
	return containsPlugin(authzPlugins, cfg.PluginName), nil
}

// PrintInstallInstructions prints manual installation instructions
func PrintInstallInstructions(cfg *InstallConfig) {
	fmt.Println("Manual installation instructions:")
	fmt.Println()
	fmt.Println("1. Add to /etc/docker/daemon.json:")
	fmt.Println("   {")
	fmt.Printf("     \"authorization-plugins\": [\"%s\"]\n", cfg.PluginName)
	fmt.Println("   }")
	fmt.Println()
	fmt.Println("2. Create plugin spec file:")
	fmt.Printf("   echo 'unix://%s' > /etc/docker/plugins/%s.spec\n", cfg.SocketPath, cfg.PluginName)
	fmt.Println()
	fmt.Println("3. Start the plugin:")
	fmt.Printf("   %s authz start\n", cfg.SentinelPath)
	fmt.Println()
	fmt.Println("4. Restart Docker:")
	fmt.Println("   sudo systemctl restart docker")
}
