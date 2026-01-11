package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rtvkiz/docker-sentinel/pkg/authz"
	serrors "github.com/rtvkiz/docker-sentinel/pkg/errors"
	"github.com/rtvkiz/docker-sentinel/pkg/interceptor"
	"github.com/rtvkiz/docker-sentinel/pkg/policy"
	"github.com/rtvkiz/docker-sentinel/pkg/rules"
	"github.com/rtvkiz/docker-sentinel/pkg/scanner"
	"github.com/spf13/cobra"
)

// Valid values for various flags
var (
	validScanners        = []string{"trivy", "grype", "scout"}
	validInstallMethods  = []string{"alias", "wrapper", "path"}
	validShells          = []string{"bash", "zsh", "fish"}
	validPolicyTemplates = []string{"default", "strict", "permissive", "ci-cd", "production"}
)

func runExec(cmd *cobra.Command, args []string) error {
	// Parse docker command from args
	dockerArgs := extractDockerArgs(args)
	if len(dockerArgs) == 0 {
		return serrors.MissingDockerCommand("exec")
	}

	// Validate we have at least a command
	if len(dockerArgs) == 1 && dockerArgs[0] == "docker" {
		return serrors.New(serrors.ErrMissingArgument, "No docker subcommand provided").
			WithDetail("You provided 'docker' but no subcommand (run, build, push, etc.)").
			WithSuggestion("Specify a docker subcommand after 'docker'").
			WithExample("sentinel exec -- docker run nginx:latest")
	}

	// Parse the command
	parsed, err := interceptor.ParseDockerCommand(dockerArgs)
	if err != nil {
		return serrors.ParseError(strings.Join(dockerArgs, " "), err)
	}

	// Validate the parsed command has required fields based on action
	if err := validateParsedCommand(parsed); err != nil {
		return err
	}

	// Create rule engine and validate
	engine := rules.NewEngine(cfg)
	result := engine.Validate(parsed)

	// Check if we should block
	force, _ := cmd.Flags().GetBool("force")
	if !result.Allowed && !force {
		// Print detailed findings
		printValidationResult(result)
		return serrors.New(serrors.ErrValidationFailed, "Command blocked due to security policy violations").
			WithDetail(fmt.Sprintf("Risk score: %d/100 (max allowed: %d)", result.Score, cfg.GlobalSettings.MaxRiskScore)).
			WithSuggestion("Review the risks above and apply the recommended mitigations, or use --force to bypass (not recommended)")
	}

	if len(result.Warnings) > 0 {
		printWarnings(result.Warnings)
	}

	// Handle special commands that require secret scanning
	switch parsed.Action {
	case "push":
		if parsed.Image == "" {
			return serrors.MissingArgument("image", "exec -- docker push").
				WithExample("sentinel exec -- docker push myimage:latest")
		}
		// Scan image for secrets before pushing
		if err := scanSecretsBeforePush(parsed.Image, force); err != nil {
			return err
		}
		return executeDocker(dockerArgs)

	case "build":
		// Execute build first, then scan the resulting image
		if err := executeDocker(dockerArgs); err != nil {
			return err
		}
		// Scan the built image if a tag was specified
		if parsed.Image != "" {
			return scanSecretsAfterBuild(parsed.Image, force)
		}
		return nil

	default:
		// Execute the actual docker command
		return executeDocker(dockerArgs)
	}
}

// validateParsedCommand validates the parsed command has required fields
func validateParsedCommand(cmd *interceptor.DockerCommand) error {
	switch cmd.Action {
	case "run", "create":
		if cmd.Image == "" {
			return serrors.MissingArgument("image", "exec -- docker "+cmd.Action).
				WithDetail("The 'run' command requires an image to be specified").
				WithExample("sentinel exec -- docker run nginx:latest")
		}
	case "push":
		if cmd.Image == "" {
			return serrors.MissingArgument("image", "exec -- docker push").
				WithDetail("The 'push' command requires an image to be specified").
				WithExample("sentinel exec -- docker push myregistry/myimage:v1.0")
		}
	case "pull":
		if cmd.Image == "" {
			return serrors.MissingArgument("image", "exec -- docker pull").
				WithDetail("The 'pull' command requires an image to be specified").
				WithExample("sentinel exec -- docker pull nginx:latest")
		}
	case "exec":
		if cmd.ContainerName == "" {
			return serrors.MissingArgument("container", "exec -- docker exec").
				WithDetail("The 'exec' command requires a container name or ID").
				WithExample("sentinel exec -- docker exec -it mycontainer bash")
		}
	case "build":
		if cmd.BuildContext == "" {
			return serrors.MissingArgument("build context", "exec -- docker build").
				WithDetail("The 'build' command requires a build context (path or URL)").
				WithExample("sentinel exec -- docker build -t myimage:latest .")
		}
	}
	return nil
}

// scanSecretsBeforePush scans an image for secrets before allowing push
func scanSecretsBeforePush(image string, force bool) error {
	if image == "" {
		return nil
	}

	trufflehog := scanner.NewTruffleHogScanner(cfg)
	if !trufflehog.Available() {
		fmt.Println("\033[33m⚠ TruffleHog not installed - skipping secret scan before push\033[0m")
		fmt.Println("  Install with: brew install trufflehog")
		return nil
	}

	fmt.Printf("\n\033[36m🔍 Scanning image for secrets before push: %s\033[0m\n", image)

	result, err := trufflehog.ScanSecrets(image)
	if err != nil {
		fmt.Printf("\033[33m⚠ Secret scan failed: %v\033[0m\n", err)
		if !force {
			return serrors.ScanFailed("TruffleHog", image, err).
				WithSuggestion("Use --force to push anyway (not recommended)")
		}
		return nil
	}

	if result.SecretsFound > 0 {
		scanner.PrintSecretScanResult(result)

		// Count critical/high secrets
		var critical, high, verified int
		for _, s := range result.Secrets {
			if s.Verified {
				verified++
			}
			switch s.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			}
		}

		if verified > 0 {
			fmt.Println("\n\033[31m✗ BLOCKING PUSH: Verified (active) secrets found!\033[0m")
			fmt.Println("  These secrets are confirmed to be valid credentials.")
			if !force {
				return serrors.New(serrors.ErrValidationFailed, "Push blocked: verified secrets found in image").
					WithDetail(fmt.Sprintf("Found %d verified (active) secrets", verified)).
					WithSuggestion("Remove the secrets from your image and rebuild, or use --force to bypass (DANGEROUS)")
			}
			fmt.Println("\033[33m  --force specified, allowing push despite secrets\033[0m")
		} else if critical > 0 || high > 0 {
			fmt.Printf("\n\033[31m✗ BLOCKING PUSH: Found %d critical and %d high-severity secrets\033[0m\n", critical, high)
			if !force {
				return serrors.New(serrors.ErrValidationFailed, "Push blocked: secrets found in image").
					WithDetail(fmt.Sprintf("Found %d critical and %d high-severity potential secrets", critical, high)).
					WithSuggestion("Review the findings above and remove any real secrets, or use --force to bypass")
			}
			fmt.Println("\033[33m  --force specified, allowing push despite secrets\033[0m")
		}
	} else {
		fmt.Println("\033[32m✓ No secrets found - safe to push\033[0m")
	}

	return nil
}

// scanSecretsAfterBuild scans a newly built image for secrets
func scanSecretsAfterBuild(image string, force bool) error {
	if image == "" {
		return nil
	}

	trufflehog := scanner.NewTruffleHogScanner(cfg)
	if !trufflehog.Available() {
		fmt.Println("\n\033[33m⚠ TruffleHog not installed - skipping post-build secret scan\033[0m")
		return nil
	}

	fmt.Printf("\n\033[36m🔍 Scanning built image for secrets: %s\033[0m\n", image)

	result, err := trufflehog.ScanSecrets(image)
	if err != nil {
		fmt.Printf("\033[33m⚠ Secret scan failed: %v\033[0m\n", err)
		return nil
	}

	if result.SecretsFound > 0 {
		scanner.PrintSecretScanResult(result)

		var verified int
		for _, s := range result.Secrets {
			if s.Verified {
				verified++
			}
		}

		if verified > 0 {
			fmt.Println("\n\033[31m⚠ WARNING: Built image contains verified secrets!\033[0m")
			fmt.Println("  Do NOT push this image until secrets are removed.")
		} else {
			fmt.Println("\n\033[33m⚠ WARNING: Built image may contain secrets.\033[0m")
			fmt.Println("  Review findings before pushing to registry.")
		}
	} else {
		fmt.Println("\033[32m✓ No secrets found in built image\033[0m")
	}

	return nil
}

func runValidate(cmd *cobra.Command, args []string) error {
	dockerArgs := extractDockerArgs(args)
	if len(dockerArgs) == 0 {
		return serrors.MissingDockerCommand("validate")
	}

	// Validate we have at least a command
	if len(dockerArgs) == 1 && dockerArgs[0] == "docker" {
		return serrors.New(serrors.ErrMissingArgument, "No docker subcommand provided").
			WithDetail("You provided 'docker' but no subcommand (run, build, push, etc.)").
			WithSuggestion("Specify a docker subcommand after 'docker'").
			WithExample("sentinel validate -- docker run --privileged ubuntu")
	}

	parsed, err := interceptor.ParseDockerCommand(dockerArgs)
	if err != nil {
		return serrors.ParseError(strings.Join(dockerArgs, " "), err)
	}

	// Validate the parsed command has required fields
	if err := validateParsedCommand(parsed); err != nil {
		return err
	}

	engine := rules.NewEngine(cfg)
	result := engine.Validate(parsed)

	printValidationResult(result)

	if !result.Allowed {
		os.Exit(1)
	}
	return nil
}

func runScanSecrets(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("image", "scan-secrets").
			WithDetail("The scan-secrets command requires a container image to scan").
			WithExample("sentinel scan-secrets myapp:latest")
	}

	image := args[0]
	if image == "" {
		return serrors.MissingArgument("image", "scan-secrets").
			WithDetail("Image name cannot be empty").
			WithExample("sentinel scan-secrets nginx:latest")
	}

	// Validate image format (basic check)
	if strings.HasPrefix(image, "-") {
		return serrors.InvalidArgument("image", image, "Image name cannot start with '-'. Did you forget to specify the image?").
			WithExample("sentinel scan-secrets myapp:latest")
	}

	failOnSecrets, _ := cmd.Flags().GetBool("fail-on-secrets")

	fmt.Printf("Scanning image for secrets: %s\n", image)
	fmt.Println(strings.Repeat("-", 50))

	trufflehog := scanner.NewTruffleHogScanner(cfg)

	if !trufflehog.Available() {
		return serrors.MissingDependency("TruffleHog", "secret scanning", []string{
			"brew install trufflehog",
			"pip install trufflehog",
			"go install github.com/trufflesecurity/trufflehog/v3@latest",
		})
	}

	result, err := trufflehog.ScanSecrets(image)
	if err != nil {
		// Check for common error patterns
		errStr := err.Error()
		if strings.Contains(errStr, "No such image") || strings.Contains(errStr, "not found") {
			return serrors.ImageNotFound(image).
				WithSuggestion("Pull the image first or check the image name").
				WithExample(fmt.Sprintf("docker pull %s", image))
		}
		return serrors.ScanFailed("TruffleHog", image, err)
	}

	scanner.PrintSecretScanResult(result)

	if failOnSecrets && result.SecretsFound > 0 {
		return serrors.New(serrors.ErrValidationFailed, "Secrets found in image").
			WithDetail(fmt.Sprintf("Found %d potential secrets", result.SecretsFound)).
			WithSuggestion("Remove secrets from your image or use without --fail-on-secrets flag")
	}

	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("image", "scan").
			WithDetail("The scan command requires a container image to scan for vulnerabilities").
			WithExample("sentinel scan nginx:latest")
	}

	image := args[0]
	if image == "" {
		return serrors.MissingArgument("image", "scan").
			WithDetail("Image name cannot be empty").
			WithExample("sentinel scan nginx:latest")
	}

	// Validate image format (basic check)
	if strings.HasPrefix(image, "-") {
		return serrors.InvalidArgument("image", image, "Image name cannot start with '-'. Did you forget to specify the image?").
			WithExample("sentinel scan myapp:latest")
	}

	scanners, _ := cmd.Flags().GetStringSlice("scanner")
	severity, _ := cmd.Flags().GetString("severity")
	failOn, _ := cmd.Flags().GetBool("fail-on")
	maxCritical, _ := cmd.Flags().GetInt("max-critical")
	maxHigh, _ := cmd.Flags().GetInt("max-high")

	// Validate scanners
	for _, s := range scanners {
		if !contains(validScanners, s) {
			return serrors.InvalidFlag("scanner", s, validScanners)
		}
	}

	// Validate max values
	if maxCritical < 0 {
		return serrors.InvalidArgument("max-critical", fmt.Sprintf("%d", maxCritical), "Value must be >= 0")
	}

	fmt.Printf("Scanning image: %s\n", image)
	fmt.Printf("Using scanners: %v\n", scanners)
	fmt.Println(strings.Repeat("-", 50))

	var allResults []*scanner.ScanResult
	var hasVulns bool
	var scannerErrors []string

	for _, s := range scanners {
		var sc scanner.ImageScanner
		switch s {
		case "trivy":
			sc = scanner.NewTrivyScanner(cfg)
		case "grype":
			sc = scanner.NewGrypeScanner(cfg)
		case "scout":
			sc = scanner.NewDockerScoutScanner(cfg)
		}

		// Check if scanner is available
		if !sc.Available() {
			scannerErrors = append(scannerErrors, fmt.Sprintf("%s is not installed", s))
			continue
		}

		result, err := sc.Scan(image, severity)
		if err != nil {
			scannerErrors = append(scannerErrors, fmt.Sprintf("%s: %v", s, err))
			continue
		}

		allResults = append(allResults, result)
		printScanResult(result)

		if result.TotalCritical > maxCritical || (maxHigh >= 0 && result.TotalHigh > maxHigh) {
			hasVulns = true
		}
	}

	// Report scanner errors
	if len(scannerErrors) > 0 {
		fmt.Println("\n\033[33mScanner warnings:\033[0m")
		for _, e := range scannerErrors {
			fmt.Printf("  ⚠ %s\n", e)
		}
	}

	// If no scanners succeeded, return error
	if len(allResults) == 0 {
		return serrors.New(serrors.ErrScanError, "No scanners were able to complete the scan").
			WithDetail(strings.Join(scannerErrors, "; ")).
			WithSuggestion("Install at least one scanner: trivy, grype, or docker scout")
	}

	if failOn && hasVulns {
		return serrors.New(serrors.ErrValidationFailed, "Vulnerabilities exceed threshold").
			WithDetail(fmt.Sprintf("Max critical: %d, Max high: %d", maxCritical, maxHigh)).
			WithSuggestion("Fix the vulnerabilities or adjust the thresholds")
	}

	return nil
}

func runInstall(cmd *cobra.Command, args []string) error {
	method, _ := cmd.Flags().GetString("method")
	shell, _ := cmd.Flags().GetString("shell")

	// Validate method
	if !contains(validInstallMethods, method) {
		return serrors.InvalidFlag("method", method, validInstallMethods)
	}

	// Validate shell if provided
	if shell != "" && !contains(validShells, shell) {
		return serrors.InvalidFlag("shell", shell, validShells)
	}

	if shell == "" {
		shell = detectShell()
	}

	fmt.Printf("Installing sentinel with method: %s for shell: %s\n", method, shell)

	switch method {
	case "alias":
		return installAlias(shell)
	case "wrapper":
		return installWrapper()
	case "path":
		return installPath()
	default:
		return serrors.InvalidFlag("method", method, validInstallMethods)
	}
}

func runPolicyShow(cmd *cobra.Command, args []string) error {
	if cfg.ActivePolicy == "" {
		return serrors.New(serrors.ErrConfigError, "No active policy configured").
			WithSuggestion("Set an active policy in your configuration or use 'sentinel policy load'")
	}

	// Use policyMgr.Load() to get the full policy.Policy struct
	pol, err := policyMgr.Load(cfg.ActivePolicy)
	if err != nil {
		return serrors.PolicyNotFound(cfg.ActivePolicy, cfg.PoliciesDir).
			WithSuggestion("Use 'sentinel policy list' to see available policies")
	}

	// Header
	fmt.Printf("Active Policy: %s\n", pol.Name)
	if pol.Mode != "" {
		fmt.Printf("Mode: %s\n", pol.Mode)
	} else {
		fmt.Printf("Mode: %s\n", cfg.Mode)
	}
	if pol.Description != "" {
		fmt.Printf("Description: %s\n", pol.Description)
	}
	fmt.Println(strings.Repeat("-", 50))

	// Settings
	fmt.Printf("\n\033[36mSettings:\033[0m\n")
	fmt.Printf("  Max Risk Score:     %d\n", pol.Settings.MaxRiskScore)
	fmt.Printf("  Require Image Scan: %v\n", pol.Settings.RequireImageScan)

	// Rules - Privileged
	fmt.Printf("\n\033[36mPrivileged Mode:\033[0m\n")
	fmt.Printf("  Action: %s\n", pol.Rules.Privileged.Action)

	// Rules - Host Namespaces
	fmt.Printf("\n\033[36mHost Namespaces:\033[0m\n")
	fmt.Printf("  Network: %s\n", pol.Rules.HostNamespaces.Network.Action)
	fmt.Printf("  PID:     %s\n", pol.Rules.HostNamespaces.PID.Action)
	fmt.Printf("  IPC:     %s\n", pol.Rules.HostNamespaces.IPC.Action)
	fmt.Printf("  UTS:     %s\n", pol.Rules.HostNamespaces.UTS.Action)

	// Rules - Capabilities
	if len(pol.Rules.Capabilities.Blocked) > 0 {
		fmt.Printf("\n\033[36mBlocked Capabilities:\033[0m\n")
		for _, cap := range pol.Rules.Capabilities.Blocked {
			if cap.Message != "" {
				fmt.Printf("  - %s (%s)\n", cap.Name, cap.Message)
			} else {
				fmt.Printf("  - %s\n", cap.Name)
			}
		}
	}

	// Rules - Mounts
	if len(pol.Rules.Mounts.Blocked) > 0 {
		fmt.Printf("\n\033[36mBlocked Mounts:\033[0m\n")
		for _, mount := range pol.Rules.Mounts.Blocked {
			if mount.Message != "" {
				fmt.Printf("  - %s (%s)\n", mount.Path, mount.Message)
			} else {
				fmt.Printf("  - %s\n", mount.Path)
			}
		}
	}

	if len(pol.Rules.Mounts.Warned) > 0 {
		fmt.Printf("\n\033[36mWarned Mounts:\033[0m\n")
		for _, mount := range pol.Rules.Mounts.Warned {
			if mount.Message != "" {
				fmt.Printf("  - %s (%s)\n", mount.Path, mount.Message)
			} else {
				fmt.Printf("  - %s\n", mount.Path)
			}
		}
	}

	// Rules - Images/Registries
	if len(pol.Rules.Images.AllowedRegistries) > 0 {
		fmt.Printf("\n\033[36mAllowed Registries:\033[0m\n")
		for _, reg := range pol.Rules.Images.AllowedRegistries {
			fmt.Printf("  - %s\n", reg)
		}
	}

	// Security Options
	fmt.Printf("\n\033[36mSecurity Options:\033[0m\n")
	fmt.Printf("  Require Seccomp:  %v\n", pol.Rules.SecurityOptions.RequireSeccomp)
	fmt.Printf("  Require AppArmor: %v\n", pol.Rules.SecurityOptions.RequireApparmor)

	// Container Rules
	fmt.Printf("\n\033[36mContainer Rules:\033[0m\n")
	fmt.Printf("  Require Non-Root:       %v\n", pol.Rules.Container.RequireNonRoot)
	fmt.Printf("  Require Resource Limits: %v\n", pol.Rules.Container.RequireResourceLimits)

	// Image Rules
	fmt.Printf("\n\033[36mImage Rules:\033[0m\n")
	fmt.Printf("  Block :latest Tag: %v\n", pol.Rules.Images.BlockLatestTag)
	fmt.Printf("  Require Digest:    %v\n", pol.Rules.Images.RequireDigest)

	// Custom Rules
	if len(pol.CustomRules) > 0 {
		fmt.Printf("\n\033[36mCustom Rules:\033[0m\n")
		for _, rule := range pol.CustomRules {
			fmt.Printf("  - %s [%s]: %s\n", rule.Name, rule.Severity, rule.Description)
		}
	}

	return nil
}

func runPolicyLoad(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("policy file", "policy load").
			WithDetail("Specify the path to a policy YAML file to load").
			WithExample("sentinel policy load ./my-policy.yaml")
	}

	policyFile := args[0]
	if policyFile == "" {
		return serrors.MissingArgument("policy file", "policy load").
			WithExample("sentinel policy load ./my-policy.yaml")
	}

	// Check if file exists
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		return serrors.New(serrors.ErrNotFound, fmt.Sprintf("Policy file not found: %s", policyFile)).
			WithSuggestion("Check the file path and ensure the file exists")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(policyFile))
	if ext != ".yaml" && ext != ".yml" {
		return serrors.InvalidArgument("policy file", policyFile, "Policy file must be a YAML file (.yaml or .yml)")
	}

	// Load and validate the policy
	loadedPolicy, err := policyMgr.LoadFromFile(policyFile)
	if err != nil {
		return serrors.PolicyLoadError(policyFile, err)
	}

	// Save to policies directory
	if err := policyMgr.Save(loadedPolicy); err != nil {
		return serrors.New(serrors.ErrPolicyError, "Failed to save policy").
			WithDetail(err.Error())
	}

	fmt.Printf("\033[32m✓\033[0m Policy '%s' loaded and saved to %s\n", loadedPolicy.Name, cfg.PoliciesDir)
	fmt.Printf("  To activate: sentinel policy use %s\n", loadedPolicy.Name)
	return nil
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	policies, err := policyMgr.List()
	if err != nil {
		return serrors.New(serrors.ErrPolicyError, "Failed to list policies").
			WithDetail(err.Error())
	}

	if len(policies) == 0 {
		fmt.Println("\033[33mNo policies found.\033[0m")
		fmt.Printf("Policies directory: %s\n", cfg.PoliciesDir)
		fmt.Println("\nCreate a policy with: sentinel policy create my-policy")
		return nil
	}

	fmt.Printf("\033[36mAvailable Policies:\033[0m (%s)\n", cfg.PoliciesDir)
	fmt.Println(strings.Repeat("-", 60))

	for _, p := range policies {
		// Mark active policy
		activeMarker := "  "
		if p.Name == cfg.ActivePolicy {
			activeMarker = "\033[32m→\033[0m "
		}

		// Mode indicator
		modeColor := "\033[33m" // yellow for warn
		if p.Mode == "enforce" {
			modeColor = "\033[31m" // red for enforce
		} else if p.Mode == "audit" {
			modeColor = "\033[36m" // cyan for audit
		}

		fmt.Printf("%s%-20s %s%-8s\033[0m %s\n", activeMarker, p.Name, modeColor, p.Mode, p.Description)
	}

	fmt.Println()
	if cfg.ActivePolicy != "" {
		fmt.Printf("Active policy: \033[32m%s\033[0m\n", cfg.ActivePolicy)
	} else {
		fmt.Println("\033[33mNo active policy set.\033[0m Use: sentinel policy use <name>")
	}

	return nil
}

func runPolicyEdit(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("policy name", "policy edit").
			WithDetail("Specify the name of the policy to edit").
			WithExample("sentinel policy edit my-policy")
	}

	policyName := args[0]
	if policyName == "" {
		return serrors.MissingArgument("policy name", "policy edit")
	}

	// Validate policy name format
	if !isValidPolicyName(policyName) {
		return serrors.InvalidArgument("policy name", policyName,
			"Policy name must contain only lowercase letters, numbers, hyphens, and underscores")
	}

	policyPath := filepath.Join(cfg.PoliciesDir, policyName+".yaml")

	// Check if policy exists, if not create from template
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		templateName, _ := cmd.Flags().GetString("template")
		fmt.Printf("Policy '%s' doesn't exist. Creating from '%s' template...\n", policyName, templateName)

		// Get template policy
		templatePolicy := getTemplatePolicy(templateName)
		templatePolicy.Name = policyName
		templatePolicy.Description = fmt.Sprintf("Custom policy based on %s", templateName)

		if err := policyMgr.Save(templatePolicy); err != nil {
			return serrors.New(serrors.ErrPolicyError, "Failed to create policy").
				WithDetail(err.Error())
		}
		fmt.Printf("\033[32m✓\033[0m Created policy: %s\n", policyPath)
	}

	// Get editor from environment
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		// Try common editors
		for _, e := range []string{"vim", "vi", "nano", "code"} {
			if _, err := exec.LookPath(e); err == nil {
				editor = e
				break
			}
		}
	}
	if editor == "" {
		return serrors.New(serrors.ErrConfigError, "No editor found").
			WithDetail("Set the EDITOR environment variable or install vim/nano").
			WithExample("EDITOR=nano sentinel policy edit " + policyName)
	}

	fmt.Printf("Opening %s in %s...\n", policyPath, editor)

	// Run editor
	editorCmd := exec.Command(editor, policyPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

	if err := editorCmd.Run(); err != nil {
		return serrors.New(serrors.ErrConfigError, "Editor exited with error").
			WithDetail(err.Error())
	}

	// Validate the edited policy
	fmt.Print("\nValidating edited policy... ")
	if _, err := policyMgr.LoadFromFile(policyPath); err != nil {
		fmt.Println("\033[31m✗\033[0m")
		return serrors.PolicyLoadError(policyName, err).
			WithSuggestion("Fix the errors and run 'sentinel policy validate " + policyPath + "'")
	}
	fmt.Println("\033[32m✓\033[0m Valid")

	return nil
}

func runPolicyCreate(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("policy name", "policy create").
			WithDetail("Specify a name for the new policy").
			WithExample("sentinel policy create my-policy --template strict")
	}

	policyName := args[0]
	if policyName == "" {
		return serrors.MissingArgument("policy name", "policy create")
	}

	// Validate policy name format
	if !isValidPolicyName(policyName) {
		return serrors.InvalidArgument("policy name", policyName,
			"Policy name must contain only lowercase letters, numbers, hyphens, and underscores")
	}

	templateName, _ := cmd.Flags().GetString("template")

	// Validate template
	if !contains(validPolicyTemplates, templateName) {
		return serrors.InvalidFlag("template", templateName, validPolicyTemplates)
	}

	policyPath := filepath.Join(cfg.PoliciesDir, policyName+".yaml")

	// Check if policy already exists
	if _, err := os.Stat(policyPath); err == nil {
		return serrors.New(serrors.ErrPolicyError, fmt.Sprintf("Policy '%s' already exists", policyName)).
			WithDetail(fmt.Sprintf("File: %s", policyPath)).
			WithSuggestion("Use 'sentinel policy edit " + policyName + "' to modify it, or choose a different name")
	}

	// Get template policy
	newPolicy := getTemplatePolicy(templateName)
	newPolicy.Name = policyName
	newPolicy.Description = fmt.Sprintf("Custom policy based on %s template", templateName)

	// Save the new policy
	if err := policyMgr.Save(newPolicy); err != nil {
		return serrors.New(serrors.ErrPolicyError, "Failed to create policy").
			WithDetail(err.Error())
	}

	fmt.Printf("\033[32m✓\033[0m Created policy: %s\n", policyPath)
	fmt.Printf("  Template: %s\n", templateName)
	fmt.Printf("\n  To edit:     sentinel policy edit %s\n", policyName)
	fmt.Printf("  To activate: sentinel policy use %s\n", policyName)

	return nil
}

func runPolicyUse(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("policy name", "policy use").
			WithDetail("Specify the name of the policy to activate").
			WithExample("sentinel policy use strict")
	}

	policyName := args[0]
	if policyName == "" {
		return serrors.MissingArgument("policy name", "policy use")
	}

	// Load the policy to verify it exists and is valid
	loadedPolicy, err := policyMgr.Load(policyName)
	if err != nil {
		return serrors.PolicyNotFound(policyName, cfg.PoliciesDir).
			WithSuggestion("Use 'sentinel policy list' to see available policies")
	}

	// Update config
	if err := policyMgr.SetActive(policyName); err != nil {
		return serrors.New(serrors.ErrPolicyError, "Failed to set active policy").
			WithDetail(err.Error())
	}

	// Update the config file
	cfg.ActivePolicy = policyName
	if err := cfg.Save(); err != nil {
		fmt.Printf("\033[33m⚠\033[0m Could not save config: %v\n", err)
		fmt.Println("  The policy is active for this session but won't persist.")
	}

	fmt.Printf("\033[32m✓\033[0m Active policy set to: %s\n", policyName)
	fmt.Printf("  Mode: %s\n", loadedPolicy.Mode)
	fmt.Printf("  Description: %s\n", loadedPolicy.Description)

	// Signal the running daemon to reload the policy (if running)
	pidFile := "/var/run/sentinel-authz.pid"
	if err := authz.ReloadByPID(pidFile); err == nil {
		fmt.Printf("\033[32m✓\033[0m Daemon notified to reload policy\n")
	}
	// Silently ignore if daemon is not running - it will pick up the new policy on next start

	return nil
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("policy file", "policy validate").
			WithDetail("Specify the path to a policy YAML file to validate").
			WithExample("sentinel policy validate ./my-policy.yaml")
	}

	policyFile := args[0]

	// Check if file exists
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		// Maybe they provided a policy name instead of a file path
		policyPath := filepath.Join(cfg.PoliciesDir, policyFile+".yaml")
		if _, err := os.Stat(policyPath); err == nil {
			policyFile = policyPath
		} else {
			return serrors.New(serrors.ErrNotFound, fmt.Sprintf("Policy file not found: %s", policyFile)).
				WithSuggestion("Check the file path or use the policy name if it's in the policies directory")
		}
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(policyFile))
	if ext != ".yaml" && ext != ".yml" {
		return serrors.InvalidArgument("policy file", policyFile, "Policy file must be a YAML file (.yaml or .yml)")
	}

	fmt.Printf("Validating: %s\n", policyFile)
	fmt.Println(strings.Repeat("-", 50))

	// Load and validate
	loadedPolicy, err := policyMgr.LoadFromFile(policyFile)
	if err != nil {
		fmt.Println("\033[31m✗ Validation failed\033[0m")
		return serrors.PolicyLoadError(filepath.Base(policyFile), err)
	}

	// Additional validation
	if err := policyMgr.Validate(loadedPolicy); err != nil {
		fmt.Println("\033[31m✗ Validation failed\033[0m")
		return serrors.New(serrors.ErrPolicyError, "Policy validation failed").
			WithDetail(err.Error())
	}

	fmt.Println("\033[32m✓ Policy is valid\033[0m")
	fmt.Println()
	fmt.Printf("  Name:        %s\n", loadedPolicy.Name)
	fmt.Printf("  Version:     %s\n", loadedPolicy.Version)
	fmt.Printf("  Mode:        %s\n", loadedPolicy.Mode)
	fmt.Printf("  Description: %s\n", loadedPolicy.Description)
	fmt.Printf("  Max Risk:    %d\n", loadedPolicy.Settings.MaxRiskScore)

	return nil
}

func runPolicyDelete(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return serrors.MissingArgument("policy name", "policy delete").
			WithDetail("Specify the name of the policy to delete").
			WithExample("sentinel policy delete my-old-policy")
	}

	policyName := args[0]
	if policyName == "" {
		return serrors.MissingArgument("policy name", "policy delete")
	}

	// Can't delete default policy
	if policyName == "default" {
		return serrors.New(serrors.ErrPolicyError, "Cannot delete the default policy").
			WithSuggestion("Create a new policy instead: sentinel policy create my-policy")
	}

	policyPath := filepath.Join(cfg.PoliciesDir, policyName+".yaml")

	// Check if policy exists
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		return serrors.PolicyNotFound(policyName, cfg.PoliciesDir).
			WithSuggestion("Use 'sentinel policy list' to see available policies")
	}

	// Confirm deletion unless --force
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Printf("Delete policy '%s'? This cannot be undone. [y/N]: ", policyName)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Check if it's the active policy
	if cfg.ActivePolicy == policyName {
		fmt.Printf("\033[33m⚠\033[0m '%s' is the active policy. Setting to 'default'...\n", policyName)
		cfg.ActivePolicy = "default"
		cfg.Save()
	}

	// Delete the policy
	if err := policyMgr.Delete(policyName); err != nil {
		return serrors.New(serrors.ErrPolicyError, "Failed to delete policy").
			WithDetail(err.Error())
	}

	fmt.Printf("\033[32m✓\033[0m Deleted policy: %s\n", policyName)
	return nil
}

// getTemplatePolicy returns a policy based on the template name
func getTemplatePolicy(templateName string) *policy.Policy {
	switch templateName {
	case "strict":
		return policy.Strict()
	case "permissive":
		return policy.Permissive()
	case "ci-cd":
		// Load ci-cd from file if exists, otherwise use default
		p, err := policyMgr.Load("ci-cd")
		if err == nil {
			return p
		}
		return policy.Default()
	case "production":
		// Load production from file if exists, otherwise use strict
		p, err := policyMgr.Load("production")
		if err == nil {
			return p
		}
		return policy.Strict()
	default:
		return policy.Default()
	}
}

// isValidPolicyName checks if a policy name is valid
func isValidPolicyName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Helper functions

func extractDockerArgs(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return args
}

func executeDocker(args []string) error {
	dockerPath := findDocker()
	if dockerPath == "" {
		return serrors.MissingDependency("docker", "executing container commands", []string{
			"Install Docker Desktop: https://www.docker.com/products/docker-desktop",
			"Install Docker Engine: https://docs.docker.com/engine/install/",
		})
	}

	cmd := exec.Command(dockerPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func findDocker() string {
	// Check for renamed docker binary first
	paths := []string{
		"/usr/bin/docker-real",
		"/usr/local/bin/docker-real",
		"/usr/bin/docker",
		"/usr/local/bin/docker",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Try to find docker in PATH
	path, err := exec.LookPath("docker")
	if err == nil {
		return path
	}

	return ""
}

func detectShell() string {
	shell := os.Getenv("SHELL")
	if strings.Contains(shell, "zsh") {
		return "zsh"
	} else if strings.Contains(shell, "fish") {
		return "fish"
	}
	return "bash"
}

func installAlias(shell string) error {
	var rcFile string
	var aliasLine string

	switch shell {
	case "zsh":
		rcFile = os.Getenv("HOME") + "/.zshrc"
		aliasLine = "alias docker='sentinel exec --'"
	case "fish":
		rcFile = os.Getenv("HOME") + "/.config/fish/config.fish"
		aliasLine = "alias docker 'sentinel exec --'"
	default:
		rcFile = os.Getenv("HOME") + "/.bashrc"
		aliasLine = "alias docker='sentinel exec --'"
	}

	fmt.Printf("Add the following line to %s:\n\n", rcFile)
	fmt.Printf("  %s\n\n", aliasLine)
	fmt.Println("Then restart your shell or run: source", rcFile)

	return nil
}

func installWrapper() error {
	fmt.Println("Wrapper installation requires sudo access.")
	fmt.Println("\nRun these commands:")
	fmt.Println("  sudo mv /usr/bin/docker /usr/bin/docker-real")
	fmt.Println("  sudo ln -s $(which sentinel) /usr/bin/docker")
	return nil
}

func installPath() error {
	fmt.Println("PATH installation requires sudo access.")
	fmt.Println("\nRun these commands:")
	fmt.Println("  sudo mv /usr/bin/docker /usr/bin/docker-real")
	fmt.Println("  sudo cp $(which sentinel) /usr/bin/docker")
	return nil
}

func printValidationResult(result *rules.ValidationResult) {
	if result.Allowed {
		fmt.Println("\n\033[32m✓ Command ALLOWED\033[0m")
	} else {
		fmt.Println("\n\033[31m✗ Command BLOCKED\033[0m")
	}

	fmt.Printf("Risk Score: %d/100\n", result.Score)
	fmt.Println(strings.Repeat("-", 50))

	if len(result.Risks) > 0 {
		fmt.Println("\n\033[31mRisks Detected:\033[0m")
		for _, risk := range result.Risks {
			fmt.Printf("  [%s] %s: %s\n", risk.Level, risk.Category, risk.Description)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n\033[33mWarnings:\033[0m")
		for _, warning := range result.Warnings {
			fmt.Printf("  ⚠ %s\n", warning.Message)
		}
	}

	if len(result.Mitigations) > 0 {
		fmt.Println("\n\033[36mRecommended Mitigations:\033[0m")
		for _, m := range result.Mitigations {
			fmt.Printf("  → %s\n", m)
		}
	}
}

func printWarnings(warnings []rules.Warning) {
	fmt.Println("\n\033[33mWarnings:\033[0m")
	for _, warning := range warnings {
		fmt.Printf("  ⚠ %s\n", warning.Message)
	}
}

func printScanResult(result *scanner.ScanResult) {
	fmt.Printf("\nScanner: %s\n", result.Scanner)
	fmt.Printf("Image: %s\n", result.Image)
	fmt.Printf("Scanned: %s\n", result.ScannedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Printf("  Critical: %d\n", result.TotalCritical)
	fmt.Printf("  High:     %d\n", result.TotalHigh)
	fmt.Printf("  Medium:   %d\n", result.TotalMedium)
	fmt.Printf("  Low:      %d\n", result.TotalLow)

	if len(result.Vulnerabilities) > 0 {
		fmt.Println("\nTop Vulnerabilities:")
		max := 10
		if len(result.Vulnerabilities) < max {
			max = len(result.Vulnerabilities)
		}
		for i := 0; i < max; i++ {
			v := result.Vulnerabilities[i]
			fmt.Printf("  %s [%s] %s %s\n", v.CVE, v.Severity, v.Package, v.Version)
		}
	}
}

// contains checks if a string slice contains a value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
