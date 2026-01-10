package main

import (
	"fmt"
	"os"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/authz"
	serrors "github.com/rtvkiz/docker-sentinel/pkg/errors"
	"github.com/spf13/cobra"
)

var authzCmd = &cobra.Command{
	Use:   "authz",
	Short: "Manage the Docker authorization plugin",
	Long: `Manage the Docker Sentinel authorization plugin.

The authorization plugin intercepts Docker API requests at the daemon level,
providing enterprise-grade security enforcement that cannot be bypassed.

Example:
  sentinel authz start     # Start the plugin daemon
  sentinel authz status    # Check plugin status
  sentinel authz install   # Configure Docker to use the plugin`,
}

var authzStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the authorization plugin daemon",
	Long: `Starts the Docker Sentinel authorization plugin daemon.

The daemon listens on a Unix socket and intercepts all Docker API requests,
evaluating them against the configured security policy.

Example:
  sentinel authz start                    # Start with defaults
  sentinel authz start --foreground       # Run in foreground (for systemd)
  sentinel authz start --policy strict    # Use specific policy`,
	RunE:          runAuthzStart,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var authzStopCmd = &cobra.Command{
	Use:           "stop",
	Short:         "Stop the authorization plugin daemon",
	RunE:          runAuthzStop,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var authzStatusCmd = &cobra.Command{
	Use:           "status",
	Short:         "Check the status of the authorization plugin",
	RunE:          runAuthzStatus,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var authzInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Configure Docker to use the Sentinel authorization plugin",
	Long: `Configures Docker to use the Sentinel authorization plugin.

This command:
1. Updates /etc/docker/daemon.json to add the authorization plugin
2. Creates the plugin spec file in /etc/docker/plugins/
3. Optionally installs a systemd service
4. Optionally restarts Docker

Requires root privileges.

Example:
  sudo sentinel authz install
  sudo sentinel authz install --systemd --restart-docker`,
	RunE:          runAuthzInstall,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var authzUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove Sentinel authorization plugin from Docker",
	Long: `Removes the Sentinel authorization plugin from Docker configuration.

This command:
1. Removes the plugin from /etc/docker/daemon.json
2. Removes the plugin spec file
3. Optionally removes the systemd service
4. Optionally restarts Docker

Requires root privileges.`,
	RunE:          runAuthzUninstall,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var authzReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload the authorization plugin's policy configuration",
	Long: `Sends a SIGHUP signal to the running daemon to reload its policy.

This is useful when:
- You've edited a policy file and want to apply changes
- You've switched the active policy with 'sentinel policy use'
- You want to manually trigger a policy refresh

The daemon will reload the policy without restarting, maintaining
all existing connections and state.

Example:
  sentinel authz reload`,
	RunE:          runAuthzReload,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	// Start command flags
	authzStartCmd.Flags().String("socket", "/run/docker/plugins/sentinel.sock", "Unix socket path")
	authzStartCmd.Flags().String("policy", "", "Policy to use (default: active policy from config)")
	authzStartCmd.Flags().Bool("foreground", false, "Run in foreground (for systemd)")
	authzStartCmd.Flags().Bool("fail-open", false, "Allow requests on error (default: fail-closed)")
	authzStartCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	authzStartCmd.Flags().Bool("hot-reload", true, "Enable automatic policy reload on file changes")
	authzStartCmd.Flags().Duration("hot-reload-debounce", 500*time.Millisecond, "Debounce duration for hot reload")

	// Install command flags
	authzInstallCmd.Flags().String("docker-config", "/etc/docker/daemon.json", "Path to Docker daemon.json")
	authzInstallCmd.Flags().Bool("systemd", false, "Also install systemd service")
	authzInstallCmd.Flags().Bool("restart-docker", false, "Restart Docker after installation")

	// Uninstall command flags
	authzUninstallCmd.Flags().Bool("systemd", false, "Also remove systemd service")
	authzUninstallCmd.Flags().Bool("restart-docker", false, "Restart Docker after uninstallation")

	// Build command tree
	authzCmd.AddCommand(authzStartCmd, authzStopCmd, authzStatusCmd, authzInstallCmd, authzUninstallCmd, authzReloadCmd)
}

func runAuthzStart(cmd *cobra.Command, args []string) error {
	socketPath, _ := cmd.Flags().GetString("socket")
	policyName, _ := cmd.Flags().GetString("policy")
	foreground, _ := cmd.Flags().GetBool("foreground")
	failOpen, _ := cmd.Flags().GetBool("fail-open")
	logLevel, _ := cmd.Flags().GetString("log-level")
	hotReload, _ := cmd.Flags().GetBool("hot-reload")
	hotReloadDebounce, _ := cmd.Flags().GetDuration("hot-reload-debounce")

	// Use active policy from config if not specified on command line
	if policyName == "" {
		policyName = cfg.ActivePolicy
	}
	fmt.Printf("[DEBUG] ConfigDir=%s, PoliciesDir=%s, ActivePolicy=%s, policyName=%s\n",
		cfg.ConfigDir, cfg.PoliciesDir, cfg.ActivePolicy, policyName)

	// Check if running as root
	if os.Geteuid() != 0 {
		return serrors.New(serrors.ErrPermissionError, "Must run as root").
			WithSuggestion("Use sudo to run this command").
			WithExample("sudo sentinel authz start")
	}

	// Build plugin config
	pluginCfg := authz.DefaultPluginConfig()
	pluginCfg.SocketPath = socketPath
	pluginCfg.PolicyName = policyName
	pluginCfg.FailClosed = !failOpen
	pluginCfg.LogLevel = logLevel
	pluginCfg.PoliciesDir = cfg.PoliciesDir
	pluginCfg.HotReload = hotReload
	pluginCfg.HotReloadDebounce = hotReloadDebounce

	// Create and start daemon
	daemon, err := authz.NewDaemon(pluginCfg)
	if err != nil {
		return serrors.New(serrors.ErrConfigError, "Failed to create daemon").
			WithDetail(err.Error())
	}

	fmt.Printf("Starting Docker Sentinel authorization plugin...\n")
	fmt.Printf("  Socket: %s\n", socketPath)
	if policyName != "" {
		fmt.Printf("  Policy: %s\n", policyName)
	} else {
		fmt.Printf("  Policy: %s (active)\n", cfg.ActivePolicy)
	}
	fmt.Printf("  Mode: %s\n", map[bool]string{true: "fail-open", false: "fail-closed"}[failOpen])
	if hotReload {
		fmt.Printf("  Hot Reload: enabled (debounce: %v)\n", hotReloadDebounce)
	} else {
		fmt.Printf("  Hot Reload: disabled\n")
	}
	fmt.Println()

	// daemon.Start() blocks until shutdown signal or error
	if err := daemon.Start(foreground); err != nil {
		return serrors.New(serrors.ErrConfigError, "Failed to start daemon").
			WithDetail(err.Error())
	}

	fmt.Println("\033[32m✓\033[0m Daemon stopped")
	return nil
}

func runAuthzStop(cmd *cobra.Command, args []string) error {
	pidFile := "/var/run/sentinel-authz.pid"

	fmt.Println("Stopping Docker Sentinel authorization plugin...")

	if err := authz.StopByPID(pidFile); err != nil {
		return serrors.New(serrors.ErrNotFound, "Failed to stop daemon").
			WithDetail(err.Error()).
			WithSuggestion("The daemon may not be running")
	}

	fmt.Println("\033[32m✓\033[0m Daemon stopped")
	return nil
}

func runAuthzStatus(cmd *cobra.Command, args []string) error {
	pidFile := "/var/run/sentinel-authz.pid"
	socketPath := "/run/docker/plugins/sentinel.sock"

	status, err := authz.GetStatus(pidFile, socketPath)
	if err != nil {
		return serrors.New(serrors.ErrConfigError, "Failed to get status").
			WithDetail(err.Error())
	}

	if status.Running {
		fmt.Println("\033[32m●\033[0m Docker Sentinel AuthZ Plugin")
		fmt.Printf("  Status:  \033[32mRunning\033[0m\n")
		fmt.Printf("  PID:     %d\n", status.PID)
		if status.SocketPath != "" {
			fmt.Printf("  Socket:  %s\n", status.SocketPath)
		}
		if status.PolicyName != "" {
			fmt.Printf("  Policy:  %s\n", status.PolicyName)
		}
		if status.Uptime != "" {
			fmt.Printf("  Uptime:  %s\n", status.Uptime)
		}
	} else {
		fmt.Println("\033[31m○\033[0m Docker Sentinel AuthZ Plugin")
		fmt.Printf("  Status:  \033[31mNot running\033[0m\n")
		fmt.Printf("  Message: %s\n", status.Message)
		fmt.Println()
		fmt.Println("To start: sudo sentinel authz start")
	}

	// Check if installed in Docker
	installCfg := authz.DefaultInstallConfig()
	installed, _ := authz.IsInstalled(installCfg)
	fmt.Println()
	if installed {
		fmt.Println("\033[32m✓\033[0m Installed in Docker configuration")
	} else {
		fmt.Println("\033[33m○\033[0m Not installed in Docker configuration")
		fmt.Println("  To install: sudo sentinel authz install")
	}

	return nil
}

func runAuthzInstall(cmd *cobra.Command, args []string) error {
	dockerConfig, _ := cmd.Flags().GetString("docker-config")
	installSystemd, _ := cmd.Flags().GetBool("systemd")
	restartDocker, _ := cmd.Flags().GetBool("restart-docker")

	// Check if running as root
	if os.Geteuid() != 0 {
		return serrors.New(serrors.ErrPermissionError, "Must run as root").
			WithSuggestion("Use sudo to run this command").
			WithExample("sudo sentinel authz install")
	}

	installCfg := authz.DefaultInstallConfig()
	installCfg.DockerConfigPath = dockerConfig

	fmt.Println("Installing Docker Sentinel authorization plugin...")
	fmt.Println()

	// Install Docker configuration
	fmt.Print("  Configuring Docker... ")
	if err := authz.Install(installCfg); err != nil {
		fmt.Println("\033[31m✗\033[0m")
		return serrors.New(serrors.ErrConfigError, "Failed to configure Docker").
			WithDetail(err.Error())
	}
	fmt.Println("\033[32m✓\033[0m")

	// Install systemd service if requested
	if installSystemd {
		fmt.Print("  Installing systemd service... ")
		if err := authz.InstallSystemdService(installCfg); err != nil {
			fmt.Println("\033[31m✗\033[0m")
			return serrors.New(serrors.ErrConfigError, "Failed to install systemd service").
				WithDetail(err.Error())
		}
		fmt.Println("\033[32m✓\033[0m")
	}

	// Restart Docker if requested
	if restartDocker {
		fmt.Print("  Restarting Docker... ")
		if err := authz.RestartDocker(); err != nil {
			fmt.Println("\033[31m✗\033[0m")
			return serrors.New(serrors.ErrConfigError, "Failed to restart Docker").
				WithDetail(err.Error()).
				WithSuggestion("You may need to restart Docker manually: sudo systemctl restart docker")
		}
		fmt.Println("\033[32m✓\033[0m")
	}

	fmt.Println()
	fmt.Println("\033[32m✓\033[0m Installation complete!")
	fmt.Println()
	fmt.Println("Next steps:")
	if !installSystemd {
		fmt.Println("  1. Start the plugin:  sudo sentinel authz start")
		fmt.Println("  2. Restart Docker:    sudo systemctl restart docker")
	} else {
		fmt.Println("  1. Start the service: sudo systemctl start docker-sentinel")
		fmt.Println("  2. Enable on boot:    sudo systemctl enable docker-sentinel")
		if !restartDocker {
			fmt.Println("  3. Restart Docker:    sudo systemctl restart docker")
		}
	}

	return nil
}

func runAuthzUninstall(cmd *cobra.Command, args []string) error {
	removeSystemd, _ := cmd.Flags().GetBool("systemd")
	restartDocker, _ := cmd.Flags().GetBool("restart-docker")

	// Check if running as root
	if os.Geteuid() != 0 {
		return serrors.New(serrors.ErrPermissionError, "Must run as root").
			WithSuggestion("Use sudo to run this command")
	}

	installCfg := authz.DefaultInstallConfig()

	fmt.Println("Uninstalling Docker Sentinel authorization plugin...")
	fmt.Println()

	// Stop daemon if running
	fmt.Print("  Stopping daemon... ")
	authz.StopByPID("/var/run/sentinel-authz.pid")
	fmt.Println("\033[32m✓\033[0m")

	// Remove systemd service if requested
	if removeSystemd {
		fmt.Print("  Removing systemd service... ")
		authz.UninstallSystemdService()
		fmt.Println("\033[32m✓\033[0m")
	}

	// Remove Docker configuration
	fmt.Print("  Removing Docker configuration... ")
	if err := authz.Uninstall(installCfg); err != nil {
		fmt.Println("\033[31m✗\033[0m")
		return serrors.New(serrors.ErrConfigError, "Failed to remove Docker configuration").
			WithDetail(err.Error())
	}
	fmt.Println("\033[32m✓\033[0m")

	// Restart Docker if requested
	if restartDocker {
		fmt.Print("  Restarting Docker... ")
		if err := authz.RestartDocker(); err != nil {
			fmt.Println("\033[31m✗\033[0m")
			fmt.Printf("  \033[33mWarning:\033[0m %v\n", err)
		} else {
			fmt.Println("\033[32m✓\033[0m")
		}
	}

	fmt.Println()
	fmt.Println("\033[32m✓\033[0m Uninstallation complete!")
	if !restartDocker {
		fmt.Println()
		fmt.Println("Note: You may need to restart Docker: sudo systemctl restart docker")
	}

	return nil
}

func runAuthzReload(cmd *cobra.Command, args []string) error {
	pidFile := "/var/run/sentinel-authz.pid"

	fmt.Println("Reloading Docker Sentinel authorization plugin...")

	if err := authz.ReloadByPID(pidFile); err != nil {
		return serrors.New(serrors.ErrNotFound, "Failed to reload daemon").
			WithDetail(err.Error()).
			WithSuggestion("Make sure the daemon is running: sudo sentinel authz start")
	}

	fmt.Println("\033[32m✓\033[0m Reload signal sent to daemon")
	fmt.Println("  The daemon will reload its policy configuration.")
	return nil
}
