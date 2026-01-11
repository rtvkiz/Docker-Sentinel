package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rtvkiz/docker-sentinel/pkg/interceptor"
	"github.com/rtvkiz/docker-sentinel/pkg/scanner"
)

// Evaluator evaluates Docker commands against policies
type Evaluator struct {
	policy    *Policy
	opaEngine *OPAEngine
}

// NewEvaluator creates a new policy evaluator
func NewEvaluator(policy *Policy, regoDir string) (*Evaluator, error) {
	e := &Evaluator{
		policy: policy,
	}

	// Initialize OPA engine if we have Rego policies
	if regoDir != "" || len(policy.Rego) > 0 {
		e.opaEngine = NewOPAEngine(regoDir)

		// Load Rego from directory
		if regoDir != "" {
			if err := e.opaEngine.LoadPoliciesFromDir(regoDir); err != nil {
				return nil, err
			}
		}

		// Load inline Rego policies
		for _, rp := range policy.Rego {
			if rp.Inline != "" {
				if err := e.opaEngine.LoadPolicy(rp.Name, rp.Inline); err != nil {
					return nil, err
				}
			} else if rp.File != "" {
				if err := e.opaEngine.LoadPolicyFile(rp.File); err != nil {
					return nil, err
				}
			}
		}
	}

	return e, nil
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	Allowed     bool
	Score       int
	Violations  []Violation
	Warnings    []Violation
	Mitigations []string
}

// Violation represents a policy violation
type Violation struct {
	Rule        string
	Severity    string
	Category    string
	Message     string
	ScoreImpact int
}

// Evaluate evaluates a Docker command against the policy
func (e *Evaluator) Evaluate(cmd *interceptor.DockerCommand) (*EvaluationResult, error) {
	result := &EvaluationResult{
		Allowed: true,
		Score:   0,
	}

	// Evaluate privileged mode
	e.evaluatePrivileged(cmd, result)

	// Evaluate host namespaces
	e.evaluateHostNamespaces(cmd, result)

	// Evaluate capabilities
	e.evaluateCapabilities(cmd, result)

	// Evaluate mounts
	e.evaluateMounts(cmd, result)

	// Evaluate security options
	e.evaluateSecurityOptions(cmd, result)

	// Evaluate container config
	e.evaluateContainer(cmd, result)

	// Evaluate images
	e.evaluateImages(cmd, result)

	// Evaluate environment
	e.evaluateEnvironment(cmd, result)

	// Evaluate custom rules
	e.evaluateCustomRules(cmd, result)

	// Evaluate OPA policies
	if e.opaEngine != nil {
		if err := e.evaluateOPA(cmd, result); err != nil {
			return nil, err
		}
	}

	// Cap score at 100
	if result.Score > 100 {
		result.Score = 100
	}

	// Determine if allowed based on mode and score
	result.Allowed = e.determineAllowed(result)

	return result, nil
}

func (e *Evaluator) evaluatePrivileged(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	if !cmd.Privileged {
		return
	}

	rule := e.policy.Rules.Privileged
	if rule.Action == "" {
		rule.Action = ActionBlock
	}

	// Check exceptions
	if e.matchesException(cmd, rule.Exceptions) {
		return
	}

	v := Violation{
		Rule:        "privileged",
		Severity:    "critical",
		Category:    "container_escape",
		Message:     "Privileged mode grants full host capabilities",
		ScoreImpact: 40,
	}

	if rule.Message != "" {
		v.Message = rule.Message
	}

	if rule.Action == ActionBlock {
		result.Violations = append(result.Violations, v)
		result.Score += v.ScoreImpact
		result.Mitigations = append(result.Mitigations, "Remove --privileged flag. Use specific capabilities with --cap-add instead.")
	} else if rule.Action == ActionWarn {
		result.Warnings = append(result.Warnings, v)
		result.Score += v.ScoreImpact // Warnings also contribute to risk score
	}
}

func (e *Evaluator) evaluateHostNamespaces(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	ns := e.policy.Rules.HostNamespaces

	// Network
	if cmd.NetworkMode == "host" {
		e.addViolation(result, ns.Network, Violation{
			Rule:        "host_network",
			Severity:    "high",
			Category:    "network_exposure",
			Message:     "Host network mode bypasses network isolation",
			ScoreImpact: 25,
		}, "Use bridge networking or create a custom network.")
	}

	// PID
	if cmd.PIDMode == "host" {
		e.addViolation(result, ns.PID, Violation{
			Rule:        "host_pid",
			Severity:    "critical",
			Category:    "container_escape",
			Message:     "Host PID namespace allows access to all host processes",
			ScoreImpact: 40,
		}, "Remove --pid=host flag.")
	}

	// IPC
	if cmd.IPCMode == "host" {
		e.addViolation(result, ns.IPC, Violation{
			Rule:        "host_ipc",
			Severity:    "high",
			Category:    "container_escape",
			Message:     "Host IPC namespace allows access to host shared memory",
			ScoreImpact: 25,
		}, "Remove --ipc=host flag.")
	}

	// UTS
	if cmd.UTSMode == "host" {
		e.addViolation(result, ns.UTS, Violation{
			Rule:        "host_uts",
			Severity:    "medium",
			Category:    "misconfiguration",
			Message:     "Host UTS namespace shares hostname with host",
			ScoreImpact: 10,
		}, "Remove --uts=host flag.")
	}
}

func (e *Evaluator) evaluateCapabilities(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	caps := e.policy.Rules.Capabilities

	for _, addedCap := range cmd.Capabilities.Add {
		cap := strings.ToUpper(addedCap)

		// Check if blocked
		for _, blocked := range caps.Blocked {
			if blocked.Name == cap || blocked.Name == "ALL" {
				v := Violation{
					Rule:        "blocked_capability",
					Severity:    "critical",
					Category:    "privilege_escalation",
					Message:     fmt.Sprintf("Blocked capability: %s", cap),
					ScoreImpact: 30,
				}
				if blocked.Message != "" {
					v.Message = blocked.Message
				}
				result.Violations = append(result.Violations, v)
				result.Score += v.ScoreImpact
				result.Mitigations = append(result.Mitigations, fmt.Sprintf("Remove --cap-add=%s", cap))
			}
		}
	}

	// Check if ALL capabilities are added
	for _, cap := range cmd.Capabilities.Add {
		if strings.ToUpper(cap) == "ALL" {
			result.Violations = append(result.Violations, Violation{
				Rule:        "all_capabilities",
				Severity:    "critical",
				Category:    "privilege_escalation",
				Message:     "Adding ALL capabilities is extremely dangerous",
				ScoreImpact: 50,
			})
			result.Score += 50
			break
		}
	}
}

func (e *Evaluator) evaluateMounts(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	mounts := e.policy.Rules.Mounts

	for _, vol := range cmd.Volumes {
		if vol.Type != interceptor.MountTypeBind {
			continue
		}

		source := vol.Source

		// Check blocked mounts
		for _, blocked := range mounts.Blocked {
			if e.matchesPath(source, blocked.Path) {
				// Skip if read-only is allowed and mount is read-only
				if blocked.AllowReadOnly && vol.ReadOnly {
					continue
				}

				v := Violation{
					Rule:        "blocked_mount",
					Severity:    "critical",
					Category:    "data_exposure",
					Message:     fmt.Sprintf("Mounting %s is blocked", source),
					ScoreImpact: 35,
				}
				if blocked.Message != "" {
					v.Message = blocked.Message
				}
				result.Violations = append(result.Violations, v)
				result.Score += v.ScoreImpact
				result.Mitigations = append(result.Mitigations, fmt.Sprintf("Remove volume mount: %s", source))
			}
		}

		// Check warned mounts
		for _, warned := range mounts.Warned {
			if e.matchesPath(source, warned.Path) {
				v := Violation{
					Rule:        "warned_mount",
					Severity:    "medium",
					Category:    "data_exposure",
					Message:     fmt.Sprintf("Mounting %s may expose sensitive data", source),
					ScoreImpact: 10,
				}
				if warned.Message != "" {
					v.Message = warned.Message
				}
				result.Warnings = append(result.Warnings, v)
				result.Score += v.ScoreImpact // Warnings also contribute to risk score
			}
		}
	}

	// Check block all bind mounts
	if mounts.BlockBindMounts {
		for _, vol := range cmd.Volumes {
			if vol.Type == interceptor.MountTypeBind {
				result.Violations = append(result.Violations, Violation{
					Rule:        "bind_mount_blocked",
					Severity:    "high",
					Category:    "data_exposure",
					Message:     fmt.Sprintf("Bind mounts are blocked: %s", vol.Source),
					ScoreImpact: 20,
				})
				result.Score += 20
			}
		}
	}
}

func (e *Evaluator) evaluateSecurityOptions(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	secOpts := e.policy.Rules.SecurityOptions

	hasSeccomp := false
	hasApparmor := false

	for _, opt := range cmd.SecurityOpts {
		if opt.Type == "seccomp" {
			hasSeccomp = true
			if opt.Value == "unconfined" {
				result.Violations = append(result.Violations, Violation{
					Rule:        "seccomp_disabled",
					Severity:    "high",
					Category:    "privilege_escalation",
					Message:     "Seccomp is disabled",
					ScoreImpact: 25,
				})
				result.Score += 25
			}
		}
		if opt.Type == "apparmor" {
			hasApparmor = true
			if opt.Value == "unconfined" {
				result.Violations = append(result.Violations, Violation{
					Rule:        "apparmor_disabled",
					Severity:    "high",
					Category:    "privilege_escalation",
					Message:     "AppArmor is disabled",
					ScoreImpact: 25,
				})
				result.Score += 25
			}
		}
	}

	// Check requirements
	if secOpts.RequireSeccomp && !hasSeccomp {
		result.Violations = append(result.Violations, Violation{
			Rule:        "seccomp_required",
			Severity:    "medium",
			Category:    "misconfiguration",
			Message:     "Seccomp profile is required",
			ScoreImpact: 15,
		})
		result.Score += 15
	}

	if secOpts.RequireApparmor && !hasApparmor {
		result.Violations = append(result.Violations, Violation{
			Rule:        "apparmor_required",
			Severity:    "medium",
			Category:    "misconfiguration",
			Message:     "AppArmor profile is required",
			ScoreImpact: 15,
		})
		result.Score += 15
	}
}

func (e *Evaluator) evaluateContainer(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	container := e.policy.Rules.Container

	// Check non-root requirement
	if container.RequireNonRoot {
		if cmd.User == "" || cmd.User == "root" || cmd.User == "0" {
			result.Violations = append(result.Violations, Violation{
				Rule:        "root_user",
				Severity:    "medium",
				Category:    "privilege_escalation",
				Message:     "Container must run as non-root user",
				ScoreImpact: 15,
			})
			result.Score += 15
			result.Mitigations = append(result.Mitigations, "Add --user flag with non-root UID")
		}
	}

	// Check read-only rootfs
	if container.RequireReadOnlyRootfs && !cmd.ReadOnlyRootfs {
		result.Violations = append(result.Violations, Violation{
			Rule:        "read_only_rootfs",
			Severity:    "low",
			Category:    "misconfiguration",
			Message:     "Read-only root filesystem is required",
			ScoreImpact: 5,
		})
		result.Score += 5
		result.Mitigations = append(result.Mitigations, "Add --read-only flag")
	}

	// Check resource limits
	if container.RequireResourceLimits {
		if cmd.Resources.Memory == "" && cmd.Resources.CPUs == "" {
			result.Violations = append(result.Violations, Violation{
				Rule:        "resource_limits",
				Severity:    "low",
				Category:    "resource_abuse",
				Message:     "Resource limits are required",
				ScoreImpact: 5,
			})
			result.Score += 5
			result.Mitigations = append(result.Mitigations, "Add --memory and --cpus flags")
		}
	}
}

func (e *Evaluator) evaluateImages(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	if cmd.Image == "" {
		return
	}

	images := e.policy.Rules.Images

	// Check registry
	registry := cmd.GetImageRegistry()
	if len(images.AllowedRegistries) > 0 {
		allowed := false
		for _, r := range images.AllowedRegistries {
			if registry == r || strings.HasPrefix(registry, r) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Violations = append(result.Violations, Violation{
				Rule:        "untrusted_registry",
				Severity:    "medium",
				Category:    "supply_chain",
				Message:     fmt.Sprintf("Registry not allowed: %s", registry),
				ScoreImpact: 15,
			})
			result.Score += 15
		}
	}

	// Check blocked registries
	for _, blocked := range images.BlockedRegistries {
		if registry == blocked {
			result.Violations = append(result.Violations, Violation{
				Rule:        "blocked_registry",
				Severity:    "high",
				Category:    "supply_chain",
				Message:     fmt.Sprintf("Registry is blocked: %s", registry),
				ScoreImpact: 25,
			})
			result.Score += 25
		}
	}

	// Check :latest tag
	if images.BlockLatestTag {
		if strings.HasSuffix(cmd.Image, ":latest") || (!strings.Contains(cmd.Image, ":") && !strings.Contains(cmd.Image, "@")) {
			result.Warnings = append(result.Warnings, Violation{
				Rule:     "latest_tag",
				Severity: "low",
				Category: "supply_chain",
				Message:  "Using :latest tag is not recommended",
			})
		}
	}

	// Check digest requirement
	if images.RequireDigest && !strings.Contains(cmd.Image, "@sha256:") {
		result.Violations = append(result.Violations, Violation{
			Rule:        "digest_required",
			Severity:    "medium",
			Category:    "supply_chain",
			Message:     "Image digest is required",
			ScoreImpact: 10,
		})
		result.Score += 10
	}
}

func (e *Evaluator) evaluateEnvironment(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	env := e.policy.Rules.Environment

	if env.BlockSecrets {
		for _, ev := range cmd.Environment {
			if ev.IsSecret && ev.Value != "" {
				result.Warnings = append(result.Warnings, Violation{
					Rule:     "secret_in_env",
					Severity: "medium",
					Category: "secret_exposure",
					Message:  fmt.Sprintf("Potential secret in environment: %s", ev.Key),
				})
			}
		}
	}
}

func (e *Evaluator) evaluateCustomRules(cmd *interceptor.DockerCommand, result *EvaluationResult) {
	for _, rule := range e.policy.CustomRules {
		if e.evaluateCondition(cmd, rule.Condition) {
			v := Violation{
				Rule:        rule.Name,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Message:     rule.Message,
				ScoreImpact: severityToScore(rule.Severity),
			}
			result.Violations = append(result.Violations, v)
			result.Score += v.ScoreImpact
		}
	}
}

func (e *Evaluator) evaluateCondition(cmd *interceptor.DockerCommand, cond RuleCondition) bool {
	// Handle AND conditions
	if len(cond.And) > 0 {
		for _, c := range cond.And {
			if !e.evaluateCondition(cmd, c) {
				return false
			}
		}
		return true
	}

	// Handle OR conditions
	if len(cond.Or) > 0 {
		for _, c := range cond.Or {
			if e.evaluateCondition(cmd, c) {
				return true
			}
		}
		return false
	}

	// Get field value
	value := e.getFieldValue(cmd, cond.Field)

	// Evaluate operator
	switch cond.Operator {
	case "equals":
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", cond.Value)
	case "not_equals":
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", cond.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	case "not_contains":
		return !strings.Contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	case "matches":
		re, err := regexp.Compile(fmt.Sprintf("%v", cond.Value))
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", value))
	case "exists":
		return value != nil && value != ""
	}

	return false
}

func (e *Evaluator) getFieldValue(cmd *interceptor.DockerCommand, field string) interface{} {
	switch field {
	case "privileged":
		return cmd.Privileged
	case "image":
		return cmd.Image
	case "user":
		return cmd.User
	case "network_mode":
		return cmd.NetworkMode
	case "pid_mode":
		return cmd.PIDMode
	default:
		return nil
	}
}

func (e *Evaluator) evaluateOPA(cmd *interceptor.DockerCommand, result *EvaluationResult) error {
	opaResult, err := e.opaEngine.Evaluate(cmd)
	if err != nil {
		return err
	}

	for _, v := range opaResult.Denied {
		result.Violations = append(result.Violations, Violation{
			Rule:        v.Policy,
			Severity:    "high",
			Category:    "policy_violation",
			Message:     v.Message,
			ScoreImpact: 25,
		})
		result.Score += 25
	}

	for _, v := range opaResult.Warnings {
		result.Warnings = append(result.Warnings, Violation{
			Rule:     v.Policy,
			Severity: "medium",
			Category: "policy_warning",
			Message:  v.Message,
		})
	}

	return nil
}

func (e *Evaluator) addViolation(result *EvaluationResult, rule RuleAction, v Violation, mitigation string) {
	if rule.Action == ActionBlock {
		if rule.Message != "" {
			v.Message = rule.Message
		}
		result.Violations = append(result.Violations, v)
		result.Score += v.ScoreImpact
		if mitigation != "" {
			result.Mitigations = append(result.Mitigations, mitigation)
		}
	} else if rule.Action == ActionWarn {
		result.Warnings = append(result.Warnings, v)
		result.Score += v.ScoreImpact // Warnings also contribute to risk score
	}
}

func (e *Evaluator) matchesException(cmd *interceptor.DockerCommand, exceptions []Exception) bool {
	for _, exc := range exceptions {
		for _, pattern := range exc.Images {
			if matched, _ := filepath.Match(pattern, cmd.Image); matched {
				return true
			}
		}
		for _, pattern := range exc.Names {
			if matched, _ := filepath.Match(pattern, cmd.ContainerName); matched {
				return true
			}
		}
	}
	return false
}

func (e *Evaluator) matchesPath(source, pattern string) bool {
	// Exact match
	if source == pattern {
		return true
	}
	// Prefix match
	if strings.HasPrefix(source, pattern+"/") {
		return true
	}
	// Glob match
	if matched, _ := filepath.Match(pattern, source); matched {
		return true
	}
	return false
}

func (e *Evaluator) determineAllowed(result *EvaluationResult) bool {
	// Audit mode: always allow, just log
	if e.policy.Mode == "audit" {
		return true
	}

	// Warn mode: always allow, but warnings are recorded
	if e.policy.Mode == "warn" {
		return true
	}

	// Enforce mode: block if there are violations or score exceeds max
	if len(result.Violations) > 0 {
		return false
	}

	if result.Score > e.policy.Settings.MaxRiskScore {
		return false
	}

	return true
}

func severityToScore(severity string) int {
	switch severity {
	case "critical":
		return 40
	case "high":
		return 25
	case "medium":
		return 15
	case "low":
		return 5
	default:
		return 10
	}
}

// SecretScanEvaluation contains the result of evaluating secret scan results against policy
type SecretScanEvaluation struct {
	Allowed     bool
	Score       int
	Violations  []Violation
	Warnings    []Violation
	Mitigations []string
}

// EvaluateSecretScan evaluates secret scan results against the policy
func (e *Evaluator) EvaluateSecretScan(result *scanner.SecretScanResult) *SecretScanEvaluation {
	eval := &SecretScanEvaluation{
		Allowed: true,
		Score:   0,
	}

	settings := e.policy.Settings.SecretScanning

	// If secret scanning is disabled, allow everything
	if !settings.Enabled {
		return eval
	}

	// No secrets found
	if result == nil || result.SecretsFound == 0 {
		return eval
	}

	// Count secrets by severity, excluding ignored detectors
	var critical, high, medium, verified int
	for _, secret := range result.Secrets {
		// Check if detector should be ignored
		if e.isDetectorIgnored(secret.DetectorType, settings.IgnoreDetectors) {
			continue
		}

		// Check if path should be excluded
		if e.isPathExcluded(secret.SourceMetadata.Data.Docker.File, settings.ExcludePaths) {
			continue
		}

		if secret.Verified {
			verified++
		}

		switch secret.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}

	// Evaluate verified secrets
	if settings.BlockOnVerified && verified > 0 {
		score := settings.VerifiedSecretScore
		if score == 0 {
			score = 50
		}
		eval.Violations = append(eval.Violations, Violation{
			Rule:        "verified_secrets",
			Severity:    "critical",
			Category:    "secret_exposure",
			Message:     fmt.Sprintf("Found %d verified (active) secret(s) in image", verified),
			ScoreImpact: score,
		})
		eval.Score += score
		eval.Mitigations = append(eval.Mitigations, "Remove or rotate exposed secrets immediately. Verified secrets are confirmed to be valid credentials.")
	}

	// Evaluate critical secrets
	if critical > settings.MaxCritical {
		score := settings.CriticalSecretScore
		if score == 0 {
			score = 40
		}
		eval.Violations = append(eval.Violations, Violation{
			Rule:        "critical_secrets",
			Severity:    "critical",
			Category:    "secret_exposure",
			Message:     fmt.Sprintf("Found %d critical secret(s) (max allowed: %d)", critical, settings.MaxCritical),
			ScoreImpact: score,
		})
		eval.Score += score
		eval.Mitigations = append(eval.Mitigations, "Review and remove high-risk secrets (AWS keys, private keys, database credentials).")
	}

	// Evaluate high severity secrets
	if high > settings.MaxHigh {
		score := settings.HighSecretScore
		if score == 0 {
			score = 25
		}
		eval.Violations = append(eval.Violations, Violation{
			Rule:        "high_secrets",
			Severity:    "high",
			Category:    "secret_exposure",
			Message:     fmt.Sprintf("Found %d high-severity secret(s) (max allowed: %d)", high, settings.MaxHigh),
			ScoreImpact: score,
		})
		eval.Score += score
		eval.Mitigations = append(eval.Mitigations, "Review and remove API keys, tokens, and other sensitive credentials.")
	}

	// Evaluate medium severity secrets (warnings only by default)
	if medium > settings.MaxMedium && settings.MaxMedium > 0 {
		eval.Warnings = append(eval.Warnings, Violation{
			Rule:     "medium_secrets",
			Severity: "medium",
			Category: "secret_exposure",
			Message:  fmt.Sprintf("Found %d medium-severity secret(s) (max allowed: %d)", medium, settings.MaxMedium),
		})
	}

	// Determine if allowed based on mode and score
	if e.policy.Mode == "audit" {
		eval.Allowed = true
	} else if len(eval.Violations) > 0 && e.policy.Mode == "enforce" {
		eval.Allowed = false
	} else if eval.Score > e.policy.Settings.MaxRiskScore {
		eval.Allowed = false
	}

	return eval
}

// isDetectorIgnored checks if a detector type should be ignored
func (e *Evaluator) isDetectorIgnored(detectorType string, ignoreList []string) bool {
	for _, ignored := range ignoreList {
		if strings.EqualFold(detectorType, ignored) {
			return true
		}
	}
	return false
}

// isPathExcluded checks if a file path should be excluded from scanning
func (e *Evaluator) isPathExcluded(filePath string, excludePaths []string) bool {
	for _, pattern := range excludePaths {
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
		// Also check if path contains the pattern
		if strings.Contains(filePath, pattern) {
			return true
		}
	}
	return false
}

// GetSecretScanSettings returns the secret scanning settings from the policy
func (e *Evaluator) GetSecretScanSettings() SecretScanSettings {
	return e.policy.Settings.SecretScanning
}
