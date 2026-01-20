# Docker Sentinel

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-20.10+-2496ED?logo=docker&logoColor=white)
[![CI](https://github.com/rtvkiz/docker-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/rtvkiz/docker-sentinel/actions/workflows/ci.yml)

**Pre-runtime Container Security for Docker**

Docker Sentinel intercepts and validates Docker commands before execution. It provides policy-based enforcement, vulnerability scanning, secret detection, and a Docker authorization plugin for daemon-level security.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Docker CLI    │────>│  Docker Daemon  │────>│    Sentinel     │
│  docker run ... │     │                 │     │  AuthZ Plugin   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │                       │
                               │   Allow / Deny        │
                               │<──────────────────────│
                               v
                       ┌─────────────┐
                       │   Execute   │
                       │  Container  │
                       └─────────────┘
```

## Features

- **Policy-Based Enforcement** - YAML-based security policies with customizable rules
- **Pre-Runtime Validation** - Block dangerous commands before they execute
- **Docker Authorization Plugin** - Daemon-level enforcement that cannot be bypassed
- **Vulnerability Scanning** - Integrated CVE scanning with Trivy, Grype, and Docker Scout
- **Secret Detection** - Automatic secret scanning on `docker push` and `docker build` with TruffleHog
- **Hot Reload** - Policy changes apply automatically without restart
- **Risk Scoring** - Quantified risk assessment (0-100) for each command
- **Audit Logging** - Complete audit trail of all Docker operations
- **JSON Output** - Machine-readable output for CI/CD integration
- **Interactive Setup** - Easy initialization wizard for new users

---

## Quick Start

### Install (Linux)

```bash
# Full installation (downloads binary, configures Docker, starts services)
# WARNING: This will restart Docker, stopping any running containers
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash
```

> **Note:** The install script automatically configures everything including the authorization plugin. You do NOT need to run `sentinel init` after using the install script.

### Verify Installation

```bash
# Run diagnostics
sudo sentinel doctor

# Check version
sentinel version
```

### Test

```bash
# Normal command - works fine
docker run nginx:latest

# Dangerous command - blocked
docker run --privileged ubuntu
#  ⛔ BLOCKED BY SENTINEL (Risk Score: 65/100)
#  🚫 [CRITICAL] Privileged containers are not allowed
#  💡 Suggested fixes:
#     → Remove --privileged flag
#     → Use specific capabilities instead: --cap-add
```

---

## Installation

### Prerequisites

- Docker 20.10+
- Root/sudo access
- Linux (authorization plugin requires systemd)
- Go 1.24+ (only for building from source)

### Installation Methods

#### 1. Install Script (Recommended for Linux)

The install script performs a complete installation:
- Downloads and installs the binary
- Creates configuration and default policies
- Installs systemd service
- Configures Docker authorization plugin
- **Restarts Docker** (stops running containers)

```bash
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash
```

#### 2. Download Binary (Manual Setup)

Use this method for more control over the installation process:

```bash
# Download latest release
curl -sSL https://github.com/rtvkiz/docker-sentinel/releases/latest/download/sentinel-linux-amd64 \
  -o /usr/local/bin/sentinel
chmod +x /usr/local/bin/sentinel

# Run interactive setup wizard
sudo sentinel init

# Optionally install authorization plugin
sudo sentinel authz install --systemd --restart-docker
```

#### 3. Build from Source

```bash
git clone https://github.com/rtvkiz/docker-sentinel.git
cd docker-sentinel
make build
sudo make install

# Run interactive setup wizard
sudo sentinel init
```

### Post-Installation Setup

> **Note:** Skip this section if you used the install script (Method 1) - it already configures everything.

```bash
# Interactive setup wizard (creates config and policies)
sudo sentinel init

# Or non-interactive with strict policy
sudo sentinel init --policy strict --no-interactive

# Install as Docker authorization plugin (Linux only)
sudo sentinel authz install --systemd --restart-docker

# Verify everything is working
sudo sentinel doctor
```

### Optional Scanners

| Tool | Purpose | Installation |
|------|---------|--------------|
| Trivy | CVE scanning | `brew install trivy` |
| Grype | CVE scanning | `brew install grype` |
| TruffleHog | Secret detection | `brew install trufflehog` |

---

## CLI Commands

> All commands require root privileges (`sudo`), except `version`.

### Quick Reference

See the full [Cheatsheet](docs/CHEATSHEET.md) for a complete command reference.

### System Commands

```bash
# Show version and build info
sentinel version
sentinel version --json

# Run diagnostics
sudo sentinel doctor
sudo sentinel doctor --json

# Interactive setup wizard
sudo sentinel init
sudo sentinel init --policy strict --no-interactive
```

### Validation

```bash
# Execute with security checks
sudo sentinel exec -- docker run nginx:latest

# Validate without executing
sudo sentinel validate -- docker run --privileged ubuntu

# JSON output for CI/CD
sudo sentinel validate --json -- docker run --privileged ubuntu
```

### Scanning

```bash
# Vulnerability scan
sudo sentinel scan nginx:latest
sudo sentinel scan --scanner trivy,grype nginx:latest
sudo sentinel scan --fail-on --max-critical 0 myapp:latest

# Secret scan
sudo sentinel scan-secrets myapp:latest
sudo sentinel scan-secrets --fail-on-secrets myapp:latest

# JSON output for CI/CD
sudo sentinel scan --json nginx:latest
sudo sentinel scan-secrets --json myapp:latest
```

### Policy Management

```bash
sudo sentinel policy list              # List policies
sudo sentinel policy show              # Show active policy
sudo sentinel policy use strict        # Switch policy
sudo sentinel policy create my-policy --template strict
sudo sentinel policy edit my-policy
sudo sentinel policy validate ./policy.yaml
sudo sentinel policy delete old-policy
```

### Authorization Plugin

```bash
sudo sentinel authz status             # Check status
sudo sentinel authz start              # Start daemon
sudo sentinel authz stop               # Stop daemon
sudo sentinel authz reload             # Reload policy
sudo sentinel authz install --systemd  # Install as systemd service
sudo sentinel authz uninstall          # Remove from Docker
```

### Audit Logs

```bash
sudo sentinel audit list               # List recent entries
sudo sentinel audit list --limit 50 --decision denied
sudo sentinel audit tail               # Live stream
sudo sentinel audit stats --since 7d   # Statistics
sudo sentinel audit export --format csv --output audit.csv
```

---

## Configuration

### Directory Structure

```
/etc/sentinel/
├── config.yaml          # Main configuration
├── policies/            # Policy files
│   ├── default.yaml
│   ├── strict.yaml
│   └── [custom].yaml
├── audit/               # Audit logs
│   ├── audit.db         # SQLite database
│   └── audit.jsonl      # JSON Lines
└── cache/               # Scan result cache
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINEL_CONFIG_DIR` | Config directory | `/etc/sentinel` |
| `EDITOR` | Editor for `policy edit` | `vim` |

---

## Policy System

### Built-in Templates

| Template | Mode | Risk Score | Use Case |
|----------|------|------------|----------|
| `default` | warn | 50 | Balanced security |
| `strict` | enforce | 25 | Maximum security |
| `permissive` | audit | 100 | Logging only |
| `production` | enforce | 50 | Production workloads |
| `ci-cd` | enforce | 40 | CI/CD pipelines |

### Example Policy

```yaml
version: "1.0"
name: my-policy
description: "Custom security policy"
mode: enforce                   # enforce | warn | audit

settings:
  max_risk_score: 50
  require_image_scan: true

rules:
  privileged:
    action: block
    exceptions:
      - images: ["docker:dind"]

  host_namespaces:
    network: { action: block }
    pid: { action: block }

  capabilities:
    blocked:
      - name: SYS_ADMIN
      - name: SYS_PTRACE

  mounts:
    blocked:
      - path: "/"
      - path: "/var/run/docker.sock"

  images:
    allowed_registries: [docker.io, gcr.io, ghcr.io]
    block_latest_tag: false
```

### Risk Scoring

| Severity | Points |
|----------|--------|
| Critical | 40 |
| High | 25 |
| Medium | 15 |
| Low | 5 |

### Policy Modes Explained

The **policy mode** determines how violations are handled:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `enforce` | **Blocks** commands that violate rules | Production environments |
| `warn` | **Allows** all commands, logs violations as warnings | Development, testing new policies |
| `audit` | **Allows** all commands, only logs for analysis | Initial rollout, monitoring |

> ⚠️ **Security Warning:** Only `enforce` mode actually prevents dangerous operations. In `warn` and `audit` modes, users can still run privileged containers and escape to host. See [Security Considerations](#️-critical-use-enforce-mode-in-production) for details.

**Important:** Policy mode is separate from rule actions.

```yaml
mode: warn          # Policy mode - determines enforcement behavior

rules:
  privileged:
    action: block   # Rule action - categorizes the violation severity
```

In **warn mode**, even rules with `action: block` will only generate warnings - they won't actually block the command. This allows you to test strict policies without impacting workflows.

### Command-Specific Rules

Different Docker commands receive different security checks:

| Command | Security Checks Applied |
|---------|------------------------|
| `run`, `create` | All checks: privileged, namespaces, capabilities, mounts, security options, user, resources, images |
| `build` | Image rules only (registry restrictions), environment (build args) |
| `push` | Image rules, **secret scanning** (blocks if secrets found) |
| `pull` | Image rules (registry restrictions) |
| `exec` | Privileged mode, capabilities, environment |
| Others (`ps`, `logs`, etc.) | No security checks (informational commands) |

---

## Secret Detection

Docker Sentinel automatically scans images for hardcoded secrets using TruffleHog.

### When Secret Scanning Occurs

| Operation | Trigger | Behavior |
|-----------|---------|----------|
| `docker push` | **Before push** | ❌ **Blocks** if critical/high/verified secrets found |
| `docker build -t image .` | **After build** | ⚠️ **Warns** (image already built) |
| `sentinel scan-secrets image` | On-demand | Reports all findings |

### Requirements

- TruffleHog must be installed: `brew install trufflehog`
- If TruffleHog is not installed, secret scanning is silently skipped

### What Gets Blocked

| Finding | Push Blocked? |
|---------|---------------|
| Verified (active) secrets | ✅ Always blocked |
| Critical severity | ✅ Blocked |
| High severity | ✅ Blocked |
| Medium severity | ⚠️ Warning only |

### Example

```bash
# Push blocked due to secrets
docker push myapp:latest
#  🔐 SECRETS DETECTED - PUSH BLOCKED
#  ─────────────────────────────────────────
#  🚫 Found 2 VERIFIED (active) secret(s) in image!
#  
#  💡 Remove secrets and rebuild the image before pushing.

# Manual scan for details
sentinel scan-secrets myapp:latest
```

---

## CI/CD Integration

Docker Sentinel provides JSON output (`--json` flag) for easy CI/CD integration.

### GitHub Actions

```yaml
- name: Install Docker Sentinel
  run: |
    curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash

- name: Security Scan
  run: |
    sentinel scan --json --fail-on --max-critical 0 myapp:${{ github.sha }}
```

### GitLab CI

```yaml
security-scan:
  before_script:
    - curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | bash
  script:
    - sentinel scan --json --fail-on --max-critical 0 $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

### More Examples

Complete CI/CD examples are available in the [examples/](examples/) directory:

- [GitHub Actions](examples/github-actions.yml)
- [GitLab CI](examples/gitlab-ci.yml)
- [Jenkins](examples/Jenkinsfile)
- [Azure Pipelines](examples/azure-pipelines.yml)

---

## JSON Output

All major commands support `--json` flag for machine-readable output:

```bash
# Validation result
sudo sentinel validate --json -- docker run --privileged ubuntu
```

```json
{
  "success": false,
  "timestamp": "2025-01-18T12:00:00Z",
  "data": {
    "allowed": false,
    "risk_score": 65,
    "max_score": 50,
    "command": "docker run --privileged ubuntu",
    "risks": [
      {
        "level": "critical",
        "category": "privileged",
        "description": "Privileged mode grants full host capabilities"
      }
    ],
    "mitigations": [
      "Remove --privileged flag",
      "Use specific capabilities instead"
    ]
  }
}
```

---

## Troubleshooting

### Quick Diagnostics

```bash
sudo sentinel doctor
```

This checks:
- Docker daemon connectivity
- Configuration and policies
- Scanner availability
- Authorization plugin status

### Common Issues

| Issue | Solution |
|-------|----------|
| "requires root privileges" | Run with `sudo` |
| "Docker daemon not running" | `sudo systemctl start docker` |
| "No policy files found" | Run `sudo sentinel init` |
| Plugin not starting | Check `journalctl -u docker-sentinel` |

### Emergency Recovery

```bash
# Temporarily disable enforcement
sudo sentinel policy use permissive

# Or stop the plugin entirely
sudo sentinel authz stop
```

For detailed troubleshooting, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [Cheatsheet](docs/CHEATSHEET.md) | Quick command reference |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Design](docs/DESIGN.md) | Architecture and internals |
| [Requirements](docs/REQUIREMENTS.md) | Detailed requirements |

---

## Security Considerations

1. **Daemon-Level Enforcement** - Cannot be bypassed by users
2. **Root Required** - All admin operations require root
3. **Fail-Closed** - Denies requests on error by default
4. **Hot Reload Safety** - Debouncing prevents rapid policy changes

### ⚠️ Critical: Use Enforce Mode in Production

**Policy mode `enforce` is essential to prevent privilege escalation.**

In `warn` or `audit` mode, non-root users with Docker access can still:
- Run privileged containers (`--privileged`)
- Mount the host filesystem (`-v /:/host`)
- Access the Docker socket (`-v /var/run/docker.sock:/var/run/docker.sock`)
- Escape container isolation and gain root access on the host

```bash
# INSECURE: Warn mode only logs, doesn't block
sudo sentinel policy use development  # mode: warn

# SECURE: Enforce mode actually blocks dangerous commands
sudo sentinel policy use production   # mode: enforce
```

**Recommendation:** Always use `mode: enforce` in production environments where non-root users have Docker access. The `warn` mode should only be used for testing policies before enforcement.

---

## Contributing

Contributions are welcome! Please see our contributing guidelines.

```bash
# Run tests
make test

# Run linter
make lint

# Build
make build
```

---

## License

MIT License - See [LICENSE](LICENSE) for details.
