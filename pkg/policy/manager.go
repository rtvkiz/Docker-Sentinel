package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manager handles policy operations
type Manager struct {
	policiesDir   string
	activePolicy  string
	loadedPolicies map[string]*Policy
}

// NewManager creates a new policy manager
func NewManager(policiesDir string) *Manager {
	return &Manager{
		policiesDir:    policiesDir,
		loadedPolicies: make(map[string]*Policy),
	}
}

// Init initializes the policy directory with default policies
func (m *Manager) Init() error {
	// Create policies directory
	if err := os.MkdirAll(m.policiesDir, 0755); err != nil {
		return fmt.Errorf("failed to create policies directory: %w", err)
	}

	// Create default policy if it doesn't exist
	defaultPath := filepath.Join(m.policiesDir, "default.yaml")
	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		if err := m.Save(Default()); err != nil {
			return fmt.Errorf("failed to save default policy: %w", err)
		}
	}

	// Create strict policy
	strictPath := filepath.Join(m.policiesDir, "strict.yaml")
	if _, err := os.Stat(strictPath); os.IsNotExist(err) {
		if err := m.Save(Strict()); err != nil {
			return fmt.Errorf("failed to save strict policy: %w", err)
		}
	}

	// Create permissive policy
	permissivePath := filepath.Join(m.policiesDir, "permissive.yaml")
	if _, err := os.Stat(permissivePath); os.IsNotExist(err) {
		if err := m.Save(Permissive()); err != nil {
			return fmt.Errorf("failed to save permissive policy: %w", err)
		}
	}

	return nil
}

// Load loads a policy by name
func (m *Manager) Load(name string) (*Policy, error) {
	// Validate policy name to prevent path traversal
	if err := m.validatePolicyName(name); err != nil {
		return nil, err
	}

	// Check cache first
	if policy, ok := m.loadedPolicies[name]; ok {
		return policy, nil
	}

	policyPath := filepath.Join(m.policiesDir, name+".yaml")

	// Double-check the resolved path is within policies directory
	absPath, err := filepath.Abs(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy path: %w", err)
	}
	absPoliciesDir, err := filepath.Abs(m.policiesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policies directory: %w", err)
	}
	if !strings.HasPrefix(absPath, absPoliciesDir+string(filepath.Separator)) {
		return nil, fmt.Errorf("invalid policy name: path traversal detected")
	}

	return m.LoadFromFile(policyPath)
}

// validatePolicyName checks if a policy name is safe
func (m *Manager) validatePolicyName(name string) error {
	if name == "" {
		return fmt.Errorf("policy name is required")
	}

	// Check for path traversal attempts
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid policy name: contains path separator or traversal")
	}

	// Check for null bytes
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("invalid policy name: contains null byte")
	}

	return nil
}

// LoadFromFile loads a policy from a specific file path
func (m *Manager) LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Validate policy
	if err := m.Validate(&policy); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	// Cache the policy
	m.loadedPolicies[policy.Name] = &policy

	return &policy, nil
}

// Save saves a policy to the policies directory
func (m *Manager) Save(policy *Policy) error {
	// Validate policy name to prevent path traversal
	if err := m.validatePolicyName(policy.Name); err != nil {
		return err
	}

	// Validate before saving
	if err := m.Validate(policy); err != nil {
		return err
	}

	policyPath := filepath.Join(m.policiesDir, policy.Name+".yaml")

	// Verify path is within policies directory
	absPath, err := filepath.Abs(policyPath)
	if err != nil {
		return fmt.Errorf("failed to resolve policy path: %w", err)
	}
	absPoliciesDir, err := filepath.Abs(m.policiesDir)
	if err != nil {
		return fmt.Errorf("failed to resolve policies directory: %w", err)
	}
	if !strings.HasPrefix(absPath, absPoliciesDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid policy name: path traversal detected")
	}

	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Add header comment
	header := fmt.Sprintf("# Docker Sentinel Policy: %s\n# %s\n\n", policy.Name, policy.Description)
	data = append([]byte(header), data...)

	// Use secure file permissions (owner read/write only)
	if err := os.WriteFile(policyPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	// Update cache
	m.loadedPolicies[policy.Name] = policy

	return nil
}

// Delete deletes a policy
func (m *Manager) Delete(name string) error {
	// Validate policy name to prevent path traversal
	if err := m.validatePolicyName(name); err != nil {
		return err
	}

	if name == "default" {
		return fmt.Errorf("cannot delete the default policy")
	}

	policyPath := filepath.Join(m.policiesDir, name+".yaml")

	// Verify path is within policies directory
	absPath, err := filepath.Abs(policyPath)
	if err != nil {
		return fmt.Errorf("failed to resolve policy path: %w", err)
	}
	absPoliciesDir, err := filepath.Abs(m.policiesDir)
	if err != nil {
		return fmt.Errorf("failed to resolve policies directory: %w", err)
	}
	if !strings.HasPrefix(absPath, absPoliciesDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid policy name: path traversal detected")
	}

	if err := os.Remove(policyPath); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	delete(m.loadedPolicies, name)
	return nil
}

// ClearCache clears all cached policies to force reload from disk
func (m *Manager) ClearCache() {
	m.loadedPolicies = make(map[string]*Policy)
}

// List returns all available policy names
func (m *Manager) List() ([]PolicyInfo, error) {
	entries, err := os.ReadDir(m.policiesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var policies []PolicyInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".yaml")
		policy, err := m.Load(name)
		if err != nil {
			continue
		}

		policies = append(policies, PolicyInfo{
			Name:        policy.Name,
			Description: policy.Description,
			Mode:        policy.Mode,
			Path:        filepath.Join(m.policiesDir, entry.Name()),
		})
	}

	return policies, nil
}

// PolicyInfo contains basic policy information
type PolicyInfo struct {
	Name        string
	Description string
	Mode        string
	Path        string
}

// Validate validates a policy configuration
func (m *Manager) Validate(policy *Policy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	// Validate name format
	for _, c := range policy.Name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return fmt.Errorf("policy name must contain only lowercase letters, numbers, hyphens, and underscores")
		}
	}

	// Validate mode
	if policy.Mode != "" && policy.Mode != "enforce" && policy.Mode != "warn" && policy.Mode != "audit" {
		return fmt.Errorf("invalid mode: %s (must be enforce, warn, or audit)", policy.Mode)
	}

	// Validate max risk score
	if policy.Settings.MaxRiskScore < 0 || policy.Settings.MaxRiskScore > 100 {
		return fmt.Errorf("max_risk_score must be between 0 and 100")
	}

	// Validate rule actions
	if err := validateRuleAction(policy.Rules.Privileged, "privileged"); err != nil {
		return err
	}
	if err := validateRuleAction(policy.Rules.HostNamespaces.Network, "host_namespaces.network"); err != nil {
		return err
	}
	if err := validateRuleAction(policy.Rules.HostNamespaces.PID, "host_namespaces.pid"); err != nil {
		return err
	}

	return nil
}

func validateRuleAction(rule RuleAction, name string) error {
	if rule.Action != "" && rule.Action != ActionAllow && rule.Action != ActionWarn && rule.Action != ActionBlock {
		return fmt.Errorf("invalid action for %s: %s (must be allow, warn, or block)", name, rule.Action)
	}
	return nil
}

// SetActive sets the active policy
func (m *Manager) SetActive(name string) error {
	// Verify policy exists
	if _, err := m.Load(name); err != nil {
		return fmt.Errorf("policy not found: %s", name)
	}
	m.activePolicy = name
	return nil
}

// GetActive returns the active policy
func (m *Manager) GetActive() (*Policy, error) {
	if m.activePolicy == "" {
		m.activePolicy = "default"
	}
	return m.Load(m.activePolicy)
}

// Copy creates a copy of an existing policy with a new name
func (m *Manager) Copy(sourceName, targetName string) error {
	source, err := m.Load(sourceName)
	if err != nil {
		return err
	}

	// Create copy
	copy := *source
	copy.Name = targetName
	copy.Description = fmt.Sprintf("Copy of %s", sourceName)

	return m.Save(&copy)
}

// Merge merges multiple policies (later policies override earlier ones)
func (m *Manager) Merge(names ...string) (*Policy, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one policy name required")
	}

	result, err := m.Load(names[0])
	if err != nil {
		return nil, err
	}

	for _, name := range names[1:] {
		policy, err := m.Load(name)
		if err != nil {
			return nil, err
		}
		mergePolicy(result, policy)
	}

	return result, nil
}

func mergePolicy(base, overlay *Policy) {
	// Merge basic fields
	if overlay.Mode != "" {
		base.Mode = overlay.Mode
	}
	if overlay.Description != "" {
		base.Description = overlay.Description
	}

	// Merge settings
	if overlay.Settings.MaxRiskScore != 0 {
		base.Settings.MaxRiskScore = overlay.Settings.MaxRiskScore
	}
	if overlay.Settings.RequireImageScan {
		base.Settings.RequireImageScan = true
	}

	// Merge image scanning settings
	if overlay.Settings.ImageScanning.Enabled {
		base.Settings.ImageScanning.Enabled = true
	}
	if len(overlay.Settings.ImageScanning.Scanners) > 0 {
		base.Settings.ImageScanning.Scanners = overlay.Settings.ImageScanning.Scanners
	}
	if overlay.Settings.ImageScanning.MaxCritical != 0 {
		base.Settings.ImageScanning.MaxCritical = overlay.Settings.ImageScanning.MaxCritical
	}
	if overlay.Settings.ImageScanning.MaxHigh != 0 {
		base.Settings.ImageScanning.MaxHigh = overlay.Settings.ImageScanning.MaxHigh
	}

	// Merge secret scanning settings
	if overlay.Settings.SecretScanning.Enabled {
		base.Settings.SecretScanning.Enabled = true
	}
	if overlay.Settings.SecretScanning.BlockOnVerified {
		base.Settings.SecretScanning.BlockOnVerified = true
	}

	// Merge privileged rule
	if overlay.Rules.Privileged.Action != "" {
		base.Rules.Privileged = overlay.Rules.Privileged
	}

	// Merge host namespace rules
	if overlay.Rules.HostNamespaces.Network.Action != "" {
		base.Rules.HostNamespaces.Network = overlay.Rules.HostNamespaces.Network
	}
	if overlay.Rules.HostNamespaces.PID.Action != "" {
		base.Rules.HostNamespaces.PID = overlay.Rules.HostNamespaces.PID
	}
	if overlay.Rules.HostNamespaces.IPC.Action != "" {
		base.Rules.HostNamespaces.IPC = overlay.Rules.HostNamespaces.IPC
	}
	if overlay.Rules.HostNamespaces.UTS.Action != "" {
		base.Rules.HostNamespaces.UTS = overlay.Rules.HostNamespaces.UTS
	}

	// Merge capability rules
	if overlay.Rules.Capabilities.DefaultAction != "" {
		base.Rules.Capabilities.DefaultAction = overlay.Rules.Capabilities.DefaultAction
	}
	if overlay.Rules.Capabilities.RequireDropAll {
		base.Rules.Capabilities.RequireDropAll = true
	}
	if len(overlay.Rules.Capabilities.Blocked) > 0 {
		base.Rules.Capabilities.Blocked = overlay.Rules.Capabilities.Blocked
	}
	if len(overlay.Rules.Capabilities.Allowed) > 0 {
		base.Rules.Capabilities.Allowed = overlay.Rules.Capabilities.Allowed
	}

	// Merge mount rules
	if overlay.Rules.Mounts.BlockBindMounts {
		base.Rules.Mounts.BlockBindMounts = true
	}
	if len(overlay.Rules.Mounts.Blocked) > 0 {
		base.Rules.Mounts.Blocked = overlay.Rules.Mounts.Blocked
	}
	if len(overlay.Rules.Mounts.Warned) > 0 {
		base.Rules.Mounts.Warned = overlay.Rules.Mounts.Warned
	}
	if len(overlay.Rules.Mounts.Allowed) > 0 {
		base.Rules.Mounts.Allowed = overlay.Rules.Mounts.Allowed
	}

	// Merge security option rules
	if overlay.Rules.SecurityOptions.RequireSeccomp {
		base.Rules.SecurityOptions.RequireSeccomp = true
	}
	if overlay.Rules.SecurityOptions.RequireApparmor {
		base.Rules.SecurityOptions.RequireApparmor = true
	}
	if overlay.Rules.SecurityOptions.RequireNoNewPrivileges {
		base.Rules.SecurityOptions.RequireNoNewPrivileges = true
	}

	// Merge container rules
	if overlay.Rules.Container.RequireNonRoot {
		base.Rules.Container.RequireNonRoot = true
	}
	if overlay.Rules.Container.RequireReadOnlyRootfs {
		base.Rules.Container.RequireReadOnlyRootfs = true
	}
	if overlay.Rules.Container.RequireResourceLimits {
		base.Rules.Container.RequireResourceLimits = true
	}
	if len(overlay.Rules.Container.BlockedUsers) > 0 {
		base.Rules.Container.BlockedUsers = overlay.Rules.Container.BlockedUsers
	}

	// Merge image rules
	if len(overlay.Rules.Images.AllowedRegistries) > 0 {
		base.Rules.Images.AllowedRegistries = overlay.Rules.Images.AllowedRegistries
	}
	if len(overlay.Rules.Images.BlockedRegistries) > 0 {
		base.Rules.Images.BlockedRegistries = overlay.Rules.Images.BlockedRegistries
	}
	if overlay.Rules.Images.BlockLatestTag {
		base.Rules.Images.BlockLatestTag = true
	}
	if overlay.Rules.Images.RequireDigest {
		base.Rules.Images.RequireDigest = true
	}

	// Merge network rules
	if len(overlay.Rules.Network.AllowedModes) > 0 {
		base.Rules.Network.AllowedModes = overlay.Rules.Network.AllowedModes
	}
	if len(overlay.Rules.Network.BlockedPorts) > 0 {
		base.Rules.Network.BlockedPorts = overlay.Rules.Network.BlockedPorts
	}
	if len(overlay.Rules.Network.RequireDNS) > 0 {
		base.Rules.Network.RequireDNS = overlay.Rules.Network.RequireDNS
	}

	// Merge environment rules
	if overlay.Rules.Environment.BlockSecrets {
		base.Rules.Environment.BlockSecrets = true
	}
	if len(overlay.Rules.Environment.SecretPatterns) > 0 {
		base.Rules.Environment.SecretPatterns = overlay.Rules.Environment.SecretPatterns
	}
	if len(overlay.Rules.Environment.Blocked) > 0 {
		base.Rules.Environment.Blocked = overlay.Rules.Environment.Blocked
	}
	if len(overlay.Rules.Environment.Required) > 0 {
		base.Rules.Environment.Required = overlay.Rules.Environment.Required
	}

	// Merge custom rules (append)
	if len(overlay.CustomRules) > 0 {
		base.CustomRules = append(base.CustomRules, overlay.CustomRules...)
	}

	// Merge Rego policies (append)
	if len(overlay.Rego) > 0 {
		base.Rego = append(base.Rego, overlay.Rego...)
	}
}

// Strict returns a strict security policy
func Strict() *Policy {
	return &Policy{
		Version:     "1.0",
		Name:        "strict",
		Description: "Strict security policy - blocks most dangerous operations",
		Mode:        "enforce",
		Settings: Settings{
			MaxRiskScore:     25,
			RequireImageScan: true,
			ImageScanning: ImageScanSettings{
				Enabled:       true,
				Scanners:      []string{"trivy", "grype"},
				MaxCritical:   0,
				MaxHigh:       0,
				CacheDuration: "1h",
			},
		},
		Rules: RulesConfig{
			Privileged: RuleAction{Action: ActionBlock, Message: "Privileged containers are not allowed"},
			HostNamespaces: HostNamespaceRules{
				Network: RuleAction{Action: ActionBlock},
				PID:     RuleAction{Action: ActionBlock},
				IPC:     RuleAction{Action: ActionBlock},
				UTS:     RuleAction{Action: ActionBlock},
			},
			Capabilities: CapabilityRules{
				DefaultAction:  ActionBlock,
				RequireDropAll: true,
				Blocked: []CapabilityRule{
					{Name: "ALL", Message: "All capabilities blocked in strict mode"},
				},
			},
			Mounts: MountRules{
				BlockBindMounts: true,
				Blocked: []MountPath{
					{Path: "/"},
					{Path: "/var/run/docker.sock"},
					{Path: "/proc"},
					{Path: "/sys"},
					{Path: "/dev"},
					{Path: "/etc"},
					{Path: "/home"},
					{Path: "/root"},
				},
			},
			SecurityOptions: SecurityOptionRules{
				RequireSeccomp:         true,
				RequireApparmor:        true,
				RequireNoNewPrivileges: true,
			},
			Container: ContainerRules{
				RequireNonRoot:        true,
				RequireReadOnlyRootfs: true,
				RequireResourceLimits: true,
				BlockedUsers:          []string{"root", "0"},
			},
			Images: ImageRules{
				AllowedRegistries: []string{"docker.io/library", "gcr.io/distroless"},
				BlockLatestTag:    true,
				RequireDigest:     true,
			},
			Environment: EnvironmentRules{
				BlockSecrets: true,
			},
		},
	}
}

// Permissive returns a permissive policy (audit only)
func Permissive() *Policy {
	return &Policy{
		Version:     "1.0",
		Name:        "permissive",
		Description: "Permissive policy - logs everything but blocks nothing",
		Mode:        "audit",
		Settings: Settings{
			MaxRiskScore:     100,
			RequireImageScan: false,
		},
		Rules: RulesConfig{
			Privileged: RuleAction{Action: ActionWarn},
			HostNamespaces: HostNamespaceRules{
				Network: RuleAction{Action: ActionWarn},
				PID:     RuleAction{Action: ActionWarn},
				IPC:     RuleAction{Action: ActionWarn},
				UTS:     RuleAction{Action: ActionWarn},
			},
			Capabilities: CapabilityRules{
				DefaultAction: ActionWarn,
			},
			Mounts: MountRules{
				Blocked: []MountPath{},
				Warned: []MountPath{
					{Path: "/"},
					{Path: "/var/run/docker.sock"},
				},
			},
			Container: ContainerRules{
				RequireNonRoot: false,
			},
			Images: ImageRules{
				AllowedRegistries: []string{},
				BlockLatestTag:    false,
			},
			Environment: EnvironmentRules{
				BlockSecrets: false,
			},
		},
	}
}
