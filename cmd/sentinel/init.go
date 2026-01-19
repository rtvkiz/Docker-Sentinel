package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
	"github.com/rtvkiz/docker-sentinel/pkg/policy"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactive setup wizard for Docker Sentinel",
	Long: `Initialize Docker Sentinel with an interactive setup wizard.

This wizard will help you:
  - Create the configuration directory
  - Choose an appropriate security policy
  - Configure scanning options
  - Optionally set up the authorization plugin

Non-interactive mode:
  sentinel init --policy strict --no-interactive`,
	RunE: runInit,
}

var (
	initPolicy        string
	initNonInteractive bool
	initInstallDaemon bool
)

func init() {
	initCmd.Flags().StringVar(&initPolicy, "policy", "", "Policy template to use (default, strict, permissive, ci-cd, production)")
	initCmd.Flags().BoolVar(&initNonInteractive, "no-interactive", false, "Run in non-interactive mode")
	initCmd.Flags().BoolVar(&initInstallDaemon, "install-daemon", false, "Install authorization plugin daemon")

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	fmt.Println("Docker Sentinel Setup Wizard")
	fmt.Println("============================")
	fmt.Println()

	// Determine config directory
	configDir := "/etc/sentinel"
	homeDir, _ := os.UserHomeDir()

	// Step 1: Create config directory
	fmt.Println("Step 1: Configuration Directory")
	fmt.Println("--------------------------------")

	if initNonInteractive {
		if err := createConfigDirectory(configDir); err != nil {
			return err
		}
	} else {
		fmt.Printf("Where should Sentinel store its configuration?\n")
		fmt.Printf("  1. %s (system-wide, recommended)\n", configDir)
		fmt.Printf("  2. %s/.sentinel (user-specific)\n", homeDir)
		fmt.Print("\nChoice [1]: ")

		choice := readInput("1")
		if choice == "2" {
			configDir = filepath.Join(homeDir, ".sentinel")
		}

		if err := createConfigDirectory(configDir); err != nil {
			return err
		}
	}
	fmt.Println()

	// Step 2: Select policy
	fmt.Println("Step 2: Security Policy")
	fmt.Println("-----------------------")

	selectedPolicy := initPolicy
	if selectedPolicy == "" {
		if initNonInteractive {
			selectedPolicy = "default"
		} else {
			fmt.Println("Choose a security policy template:")
			fmt.Println()
			fmt.Println("  1. default     - Balanced security (blocks privileged, warns on risks)")
			fmt.Println("  2. strict      - Maximum security (blocks most dangerous operations)")
			fmt.Println("  3. permissive  - Audit only (logs everything, blocks nothing)")
			fmt.Println("  4. ci-cd       - CI/CD pipelines (optimized for build environments)")
			fmt.Println("  5. production  - Production workloads (strict with reasonable defaults)")
			fmt.Print("\nChoice [1]: ")

			choice := readInput("1")
			switch choice {
			case "2":
				selectedPolicy = "strict"
			case "3":
				selectedPolicy = "permissive"
			case "4":
				selectedPolicy = "ci-cd"
			case "5":
				selectedPolicy = "production"
			default:
				selectedPolicy = "default"
			}
		}
	}

	// Validate policy name
	validPolicies := []string{"default", "strict", "permissive", "ci-cd", "production"}
	isValid := false
	for _, p := range validPolicies {
		if p == selectedPolicy {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid policy: %s (valid: %v)", selectedPolicy, validPolicies)
	}

	fmt.Printf("\n\033[32m✓\033[0m Selected policy: %s\n", selectedPolicy)
	fmt.Println()

	// Step 3: Initialize policies
	fmt.Println("Step 3: Initialize Policies")
	fmt.Println("---------------------------")

	policiesDir := filepath.Join(configDir, "policies")
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		return fmt.Errorf("failed to create policies directory: %w", err)
	}

	// Initialize policy manager and create default policies
	pm := policy.NewManager(policiesDir)
	if err := pm.Init(); err != nil {
		return fmt.Errorf("failed to initialize policies: %w", err)
	}

	// Set active policy
	if err := pm.SetActive(selectedPolicy); err != nil {
		return fmt.Errorf("failed to set active policy: %w", err)
	}

	fmt.Printf("\033[32m✓\033[0m Policies initialized in %s\n", policiesDir)
	fmt.Println()

	// Step 4: Create config file
	fmt.Println("Step 4: Create Configuration")
	fmt.Println("----------------------------")

	configPath := filepath.Join(configDir, "config.yaml")
	newConfig := config.Default()
	newConfig.ConfigDir = configDir
	newConfig.PoliciesDir = policiesDir
	newConfig.ActivePolicy = selectedPolicy
	newConfig.CacheDir = filepath.Join(configDir, "cache")

	// Create audit and cache directories
	auditDir := filepath.Join(configDir, "audit")
	os.MkdirAll(auditDir, 0755)
	os.MkdirAll(newConfig.CacheDir, 0755)

	if err := newConfig.SaveTo(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("\033[32m✓\033[0m Configuration saved to %s\n", configPath)
	fmt.Println()

	// Step 5: Optional daemon installation
	installDaemon := initInstallDaemon
	if !initNonInteractive && !installDaemon {
		fmt.Println("Step 5: Authorization Plugin (Optional)")
		fmt.Println("----------------------------------------")
		fmt.Println("The authorization plugin intercepts ALL Docker commands at the daemon level.")
		fmt.Println("This provides the strongest security but requires a Docker restart.")
		fmt.Print("\nInstall authorization plugin? [y/N]: ")

		response := readInput("n")
		installDaemon = strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
	}

	if installDaemon {
		fmt.Println()
		fmt.Println("Installing authorization plugin...")
		fmt.Println("\033[33m⚠ This will restart Docker. Running containers will be stopped.\033[0m")
		if !initNonInteractive {
			fmt.Print("Continue? [y/N]: ")
			response := readInput("n")
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Skipping daemon installation.")
				installDaemon = false
			}
		}

		if installDaemon {
			// Note: In a real implementation, this would call the authz install logic
			fmt.Println("\033[33m⚠ Run manually: sudo sentinel authz install --systemd --restart-docker\033[0m")
		}
	}

	// Summary
	fmt.Println()
	fmt.Println("Setup Complete!")
	fmt.Println("===============")
	fmt.Println()
	fmt.Printf("  Config Directory:  %s\n", configDir)
	fmt.Printf("  Policies Directory: %s\n", policiesDir)
	fmt.Printf("  Active Policy:      %s\n", selectedPolicy)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Test validation:  sudo sentinel validate -- docker run nginx")
	fmt.Println("  2. View policy:      sudo sentinel policy show")
	fmt.Println("  3. Run diagnostics:  sudo sentinel doctor")
	if !installDaemon {
		fmt.Println("  4. Install daemon:   sudo sentinel authz install --systemd --restart-docker")
	}
	fmt.Println()

	return nil
}

func createConfigDirectory(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Printf("Creating directory: %s\n", dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		fmt.Printf("\033[32m✓\033[0m Directory created\n")
	} else {
		fmt.Printf("\033[32m✓\033[0m Directory exists: %s\n", dir)
	}
	return nil
}

func readInput(defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultValue
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}
