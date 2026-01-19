# Docker Sentinel Quick Reference

## Installation

```bash
# Quick install
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash

# From source
git clone https://github.com/rtvkiz/docker-sentinel.git
cd docker-sentinel
make build && sudo make install
```

## Essential Commands

| Command | Description |
|---------|-------------|
| `sentinel version` | Show version and build info |
| `sentinel validate -- docker run ...` | Validate command without executing |
| `sentinel exec -- docker run ...` | Validate and execute command |
| `sentinel scan nginx:latest` | Scan image for vulnerabilities |
| `sentinel scan-secrets myapp:latest` | Scan image for hardcoded secrets |
| `sentinel policy list` | List available security policies |
| `sentinel policy show` | Show current active policy |
| `sentinel policy use strict` | Switch to strict policy |

## Validation Examples

```bash
# Test a command (won't execute)
sudo sentinel validate -- docker run --privileged ubuntu

# Run with security validation
sudo sentinel exec -- docker run -d nginx:latest

# Bypass security (use with caution!)
sudo sentinel exec --force -- docker run --privileged ubuntu
```

## Scanning Examples

```bash
# Basic vulnerability scan
sudo sentinel scan nginx:latest

# Scan with multiple scanners
sudo sentinel scan --scanner trivy,grype nginx:latest

# Fail CI if critical vulnerabilities found
sudo sentinel scan --fail-on --max-critical 0 myapp:latest

# Secret scanning
sudo sentinel scan-secrets myapp:latest

# Fail CI if secrets found
sudo sentinel scan-secrets --fail-on-secrets myapp:latest

# JSON output for CI/CD
sudo sentinel scan --json nginx:latest
sudo sentinel validate --json -- docker run nginx
```

## Policy Management

```bash
# List policies
sudo sentinel policy list

# Show active policy details
sudo sentinel policy show

# Switch policy
sudo sentinel policy use strict      # Maximum security
sudo sentinel policy use permissive  # Audit only (no blocking)
sudo sentinel policy use default     # Balanced

# Create custom policy
sudo sentinel policy create my-policy --template strict

# Edit policy
sudo sentinel policy edit my-policy

# Validate policy file
sudo sentinel policy validate ./my-policy.yaml
```

## Authorization Plugin (Daemon Mode)

```bash
# Install as Docker authorization plugin
sudo sentinel authz install --systemd --restart-docker

# Check plugin status
sudo sentinel authz status

# Reload policy without restart
sudo sentinel authz reload

# Stop the plugin
sudo sentinel authz stop

# Uninstall
sudo sentinel authz uninstall
```

## Audit Logs

```bash
# View recent entries
sudo sentinel audit list --limit 50

# Filter by decision
sudo sentinel audit list --decision denied

# Live tail
sudo sentinel audit tail

# Statistics
sudo sentinel audit stats --since 7d

# Export to CSV
sudo sentinel audit export --format csv --output audit.csv
```

## Emergency Commands

| Situation | Command |
|-----------|---------|
| Unblock everything temporarily | `sudo sentinel policy use permissive` |
| Stop daemon enforcement | `sudo sentinel authz stop` |
| Restore normal security | `sudo sentinel policy use default` |
| Check what's blocking | `sudo sentinel validate -- docker run ...` |

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    sudo sentinel scan --json --fail-on --max-critical 0 $IMAGE
    sudo sentinel scan-secrets --json --fail-on-secrets $IMAGE
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / Command allowed |
| 1 | Command blocked / Vulnerabilities exceed threshold |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SENTINEL_CONFIG_DIR` | Override config directory |
| `EDITOR` | Editor for `policy edit` command |

## Config Locations

| Path | Description |
|------|-------------|
| `/etc/sentinel/config.yaml` | Main configuration |
| `/etc/sentinel/policies/` | Policy files |
| `/etc/sentinel/audit/` | Audit logs |

## Useful Flags

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (for CI/CD) |
| `--verbose` | Show detailed output |
| `--force` | Bypass security checks (dangerous!) |
| `--fail-on` | Exit with error on findings |
