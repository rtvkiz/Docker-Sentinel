package main

import (
	"fmt"
	"os"

	"github.com/rtvkiz/docker-sentinel/pkg/config"
	"github.com/rtvkiz/docker-sentinel/pkg/policy"
	"github.com/spf13/cobra"
)

var (
	version   = "0.1.0"
	cfgFile   string
	cfg       *config.Config
	policyMgr *policy.Manager
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Print error without "Error:" prefix - our custom errors format themselves
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "Docker Sentinel - Pre-runtime container security",
	Long: `Docker Sentinel intercepts and validates Docker commands before execution.

It checks for dangerous flags, scans images for vulnerabilities, and enforces
security policies to prevent container escapes and privilege escalation.`,
	Version: version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Allow --help and --version for all users
		if cmd.Name() == "help" || cmd.Name() == "sentinel" {
			return nil
		}
		// Require root for all other commands
		if os.Geteuid() != 0 {
			return fmt.Errorf("sentinel requires root privileges\n\nRun with: sudo sentinel %s", cmd.Name())
		}
		return nil
	},
}

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- [docker command]",
	Short: "Execute a docker command with security validation",
	Long: `Validates the docker command against security policies before execution.
If the command passes validation, it will be executed. Otherwise, it will be blocked.

Example:
  sentinel exec -- run -d nginx
  sentinel exec -- run --privileged ubuntu  # Will be blocked`,
	RunE:               runExec,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
}

var validateCmd = &cobra.Command{
	Use:   "validate [flags] -- [docker command]",
	Short: "Validate a docker command without executing",
	Long: `Validates the docker command against security policies and reports findings.
The command will NOT be executed, only analyzed.

Example:
  sentinel validate -- run --privileged -v /:/host ubuntu`,
	RunE:               runValidate,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
}

var scanCmd = &cobra.Command{
	Use:   "scan [image]",
	Short: "Scan a container image for vulnerabilities",
	Long: `Scans the specified container image using configured scanners (Trivy, Grype, Docker Scout).

Example:
  sentinel scan nginx:latest
  sentinel scan --scanner trivy ubuntu:22.04`,
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var scanSecretsCmd = &cobra.Command{
	Use:   "scan-secrets [image]",
	Short: "Scan a container image for secrets using TruffleHog",
	Long: `Scans the specified container image for hardcoded secrets, API keys, and credentials.

Requires TruffleHog to be installed:
  brew install trufflehog
  # or
  pip install trufflehog

Example:
  sentinel scan-secrets myapp:latest
  sentinel scan-secrets --fail-on-secrets myregistry/myimage:v1.0`,
	RunE:          runScanSecrets,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install sentinel as docker command wrapper",
	Long: `Installs sentinel as a wrapper for the docker command.
This allows automatic validation of all docker commands.

Methods:
  --method alias   : Add shell alias (recommended, non-invasive)
  --method wrapper : Create wrapper script
  --method path    : Rename docker binary and symlink`,
	RunE:          runInstall,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
}

var policyShowCmd = &cobra.Command{
	Use:           "show",
	Short:         "Show current active policy",
	RunE:          runPolicyShow,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyLoadCmd = &cobra.Command{
	Use:           "load [file]",
	Short:         "Load a policy from file",
	RunE:          runPolicyLoad,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyListCmd = &cobra.Command{
	Use:           "list",
	Aliases:       []string{"ls"},
	Short:         "List all available policies",
	RunE:          runPolicyList,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyEditCmd = &cobra.Command{
	Use:   "edit [name]",
	Short: "Edit a policy in your default editor",
	Long: `Opens the specified policy in your default editor ($EDITOR).
If the policy doesn't exist, creates it from a template.

Example:
  sentinel policy edit my-policy
  EDITOR=nano sentinel policy edit my-policy`,
	RunE:          runPolicyEdit,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new policy from a template",
	Long: `Creates a new policy file from an existing template.

Templates:
  default    - Balanced security (default)
  strict     - Maximum security
  permissive - Audit-only mode
  ci-cd      - CI/CD pipeline settings
  production - Production environment

Example:
  sentinel policy create my-policy --template strict`,
	RunE:          runPolicyCreate,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyUseCmd = &cobra.Command{
	Use:   "use [name]",
	Short: "Set the active policy",
	Long: `Sets the specified policy as the active policy for command validation.

Example:
  sentinel policy use strict
  sentinel policy use my-custom-policy`,
	RunE:          runPolicyUse,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a policy file syntax and rules",
	Long: `Validates a policy file for syntax errors and rule configuration.

Example:
  sentinel policy validate ./my-policy.yaml
  sentinel policy validate ~/.sentinel/policies/custom.yaml`,
	RunE:          runPolicyValidate,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var policyDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a policy",
	Long: `Deletes a policy from the policies directory.
Note: The 'default' policy cannot be deleted.

Example:
  sentinel policy delete my-old-policy`,
	RunE:          runPolicyDelete,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sentinel/config.yaml)")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("json", false, "output in JSON format")

	// Exec command flags
	execCmd.Flags().Bool("force", false, "bypass security checks (use with caution)")
	execCmd.Flags().String("policy", "", "override policy file")

	// Scan command flags
	scanCmd.Flags().StringSlice("scanner", []string{"trivy"}, "scanners to use (trivy, grype, scout)")
	scanCmd.Flags().String("severity", "", "filter by severity (e.g., CRITICAL,HIGH,MEDIUM,LOW). Empty shows all")
	scanCmd.Flags().Bool("fail-on", false, "exit with error if vulnerabilities found")
	scanCmd.Flags().Int("max-critical", 0, "maximum allowed critical vulnerabilities")
	scanCmd.Flags().Int("max-high", -1, "maximum allowed high vulnerabilities (-1 = unlimited)")

	// Scan-secrets command flags
	scanSecretsCmd.Flags().Bool("fail-on-secrets", false, "exit with error if secrets found")
	scanSecretsCmd.Flags().Bool("verified-only", false, "only report verified (active) secrets")

	// Install command flags
	installCmd.Flags().String("method", "alias", "installation method (alias, wrapper, path)")
	installCmd.Flags().String("shell", "", "shell to configure (bash, zsh, fish)")

	// Policy create flags
	policyCreateCmd.Flags().String("template", "default", "template to use (default, strict, permissive, ci-cd, production)")

	// Policy edit flags
	policyEditCmd.Flags().String("template", "default", "template for new policy if it doesn't exist")

	// Policy delete flags
	policyDeleteCmd.Flags().Bool("force", false, "skip confirmation prompt")

	// Build command tree
	policyCmd.AddCommand(policyShowCmd, policyLoadCmd, policyListCmd, policyEditCmd, policyCreateCmd, policyUseCmd, policyValidateCmd, policyDeleteCmd)
	rootCmd.AddCommand(execCmd, validateCmd, scanCmd, scanSecretsCmd, installCmd, policyCmd, authzCmd, auditCmd)
}

func initConfig() {
	var err error
	cfg, err = config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		cfg = config.Default()
	}

	// Initialize policy manager
	policyMgr = policy.NewManager(cfg.PoliciesDir)

	// Auto-initialize policies directory with default policies if needed
	if err := policyMgr.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not initialize policies: %v\n", err)
	}
}
