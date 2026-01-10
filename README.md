# Docker Sentinel

**Pre-runtime Container Security for Docker**

Docker Sentinel is an enterprise-grade security tool that intercepts and validates Docker commands before execution. It provides policy-based enforcement, vulnerability scanning, secret detection, and a Docker authorization plugin for daemon-level security.

## How It Works

**For end users:** Users run Docker commands normally (`docker run`, `docker build`, etc.). Sentinel's authorization plugin transparently intercepts these commands at the Docker daemon level. If a command violates security policy, users see a block message explaining why.

**For administrators:** Administrators use `sudo sentinel` commands to configure policies and manage the authorization plugin. All administrative operations require root privileges.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Normal User   │────>│  Docker Daemon  │────>│    Sentinel     │
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

---

## Table of Contents

- [Features](#features)
- [Quick Start (Administrator)](#quick-start-administrator)
- [User Experience](#user-experience)
- [Installation](#installation)
- [Configuration](#configuration)
- [CLI Commands (Admin Only)](#cli-commands-admin-only)
- [Policy System](#policy-system)
- [Authorization Plugin](#authorization-plugin)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Secret Scanning](#secret-scanning)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Policy-Based Enforcement** - YAML-based security policies with customizable rules
- **Pre-Runtime Validation** - Block dangerous commands before they execute
- **Docker Authorization Plugin** - Daemon-level enforcement that cannot be bypassed
- **Vulnerability Scanning** - Integrated CVE scanning with Trivy, Grype, and Docker Scout
- **Secret Detection** - Find hardcoded secrets with TruffleHog before pushing images
- **Hot Reload** - Policy changes apply automatically without restart
- **Risk Scoring** - Quantified risk assessment (0-100) for each command
- **Multiple Deployment Modes** - CLI wrapper, shell alias, or authorization plugin

---

## Quick Start (Administrator)

### One-Line Install

```bash
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash
```

This single command will:
- Download and install the sentinel binary
- Create default configuration and policies
- Set up the systemd service
- Configure Docker to use the authorization plugin
- Start the sentinel daemon
- Restart Docker

### Verify Installation

```bash
sudo sentinel authz status
```

### That's It!

Users can now run Docker commands normally. Sentinel intercepts all requests transparently:

```bash
# User runs a normal command - works fine
docker run nginx:latest

# User tries a dangerous command - blocked by Sentinel
docker run --privileged ubuntu
# ⛔ BLOCKED BY SENTINEL (Risk Score: 65/100)
# ─────────────────────────────────────────
# 🚫 [CRITICAL] Privileged containers are not allowed
#
# 💡 Suggested fixes:
#    → Remove --privileged flag
#    → Use specific capabilities instead: --cap-add
```

---

## User Experience

Normal users interact with Docker as usual - they don't need to know about Sentinel. The authorization plugin works transparently at the Docker daemon level.

### Allowed Commands

Commands that comply with security policy execute normally:

```bash
$ docker run -d --name web nginx:1.25
abc123def456...

$ docker ps
CONTAINER ID   IMAGE        STATUS         NAMES
abc123def456   nginx:1.25   Up 2 seconds   web
```

### Blocked Commands

When a command violates security policy, users see a clear explanation:

```bash
$ docker run --privileged ubuntu bash

  ⛔ BLOCKED BY SENTINEL (Risk Score: 65/100)
  ─────────────────────────────────────────
  🚫 [CRITICAL] Privileged containers are not allowed

  💡 Suggested fixes:
     → Remove --privileged flag
     → Use specific capabilities instead: --cap-add=NET_ADMIN
```

### Warnings

Some commands may be allowed but generate warnings:

```bash
$ docker run -v /etc:/host-etc:ro nginx

  ⚠️  WARNING: Mounting /etc is potentially dangerous
  Container started with warnings. Review security implications.
```

### What Users Cannot Do

- Users cannot run `sentinel` commands directly (requires root)
- Users cannot view or modify security policies
- Users cannot bypass the authorization plugin

---

## Installation

> This section is for system administrators setting up Sentinel.

### Prerequisites

- Go 1.21+ (for building)
- Docker 20.10+
- Root/sudo access (required for all Sentinel administration)

### Optional Dependencies

| Tool | Purpose | Installation |
|------|---------|--------------|
| Trivy | Vulnerability scanning | `brew install trivy` or [trivy.dev](https://trivy.dev) |
| Grype | Vulnerability scanning | `brew install grype` or [anchore/grype](https://github.com/anchore/grype) |
| Docker Scout | Vulnerability scanning | Built into Docker Desktop |
| TruffleHog | Secret detection | `brew install trufflehog` or [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |

### Automated Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash
```

### Manual Build from Source

```bash
git clone https://github.com/rtvkiz/docker-sentinel.git
cd docker-sentinel
go build -o sentinel ./cmd/sentinel
sudo mv sentinel /usr/local/bin/

# Then install the authorization plugin
sudo sentinel authz install --systemd --restart-docker
sudo systemctl start docker-sentinel
```

### Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/uninstall.sh | sudo bash
```

### Deployment Options

#### Option 1: Authorization Plugin (Recommended)

The authorization plugin is the recommended deployment for enterprise environments. It intercepts all Docker API calls at the daemon level and cannot be bypassed by users.

```bash
sudo sentinel authz install --systemd --restart-docker
sudo systemctl start docker-sentinel
```

#### Option 2: Shell Integration (Development/Testing)

For development or testing environments, you can use shell-based interception:

```bash
# Shell Alias - for admin testing
sudo sentinel install --method alias --shell bash

# Wrapper Script
sudo sentinel install --method wrapper

# PATH Override
sudo sentinel install --method path
```

> **Note:** Shell-based methods can be bypassed by users calling Docker directly. Use the authorization plugin for production environments.

---

## Configuration

> Configuration is managed by administrators only. Normal users cannot access these files.

### Directory Structure

```
/etc/sentinel/                  # System config (recommended for production)
├── config.yaml                 # Main configuration
├── policies/                   # Policy files
│   ├── default.yaml
│   ├── strict.yaml
│   ├── permissive.yaml
│   └── [custom].yaml
└── cache/                      # Scan result cache
```

### Main Configuration (`config.yaml`)

```yaml
version: "1.0"
mode: warn                      # enforce | warn | audit
active_policy: default          # Active policy name

global_settings:
  max_risk_score: 50            # Block commands above this score
  require_image_scan: false     # Require CVE scan before run
  require_non_root: false       # Require non-root containers

image_scanning:
  enabled: true
  scanners:
    - trivy
  max_critical: 0               # Max critical CVEs allowed
  max_high: 5                   # Max high CVEs allowed
  cache_duration: 24h           # Cache scan results
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINEL_CONFIG_DIR` | Override config directory | `~/.sentinel` or `/etc/sentinel` |
| `EDITOR` | Editor for `policy edit` | `vim` |

---

## CLI Commands (Admin Only)

> All `sentinel` commands require root privileges (`sudo`). Normal users interact with Docker directly and cannot access Sentinel's CLI.

### Core Commands

#### `sentinel exec` - Execute with Validation

```bash
# Execute Docker command with security checks
sudo sentinel exec -- docker run nginx:latest

# Force execution despite violations (not recommended)
sudo sentinel exec --force -- docker run --privileged ubuntu
```

#### `sentinel validate` - Validate Without Executing

```bash
# Check if command would be allowed
sudo sentinel validate -- docker run --privileged ubuntu

# Exit code: 0 = allowed, 1 = blocked
```

### Scanning Commands

#### `sentinel scan` - Vulnerability Scanning

```bash
# Scan image for CVEs
sudo sentinel scan nginx:latest

# Use specific scanners
sudo sentinel scan --scanner trivy,grype myapp:v1.0

# Fail if vulnerabilities found
sudo sentinel scan --fail-on --max-critical 0 --max-high 3 myapp:latest
```

#### `sentinel scan-secrets` - Secret Detection

```bash
# Scan image for hardcoded secrets
sudo sentinel scan-secrets myapp:latest

# Fail CI/CD if secrets found
sudo sentinel scan-secrets --fail-on-secrets myapp:latest
```

### Policy Commands

#### `sentinel policy list` - List Policies

```bash
sudo sentinel policy list
# or
sudo sentinel policy ls
```

#### `sentinel policy show` - Show Active Policy

```bash
sudo sentinel policy show
```

#### `sentinel policy use` - Switch Policy

```bash
sudo sentinel policy use strict
```

#### `sentinel policy create` - Create New Policy

```bash
# Create from template
sudo sentinel policy create my-policy --template strict

# Available templates: default, strict, permissive, ci-cd, production
```

#### `sentinel policy edit` - Edit Policy

```bash
sudo sentinel policy edit my-policy
```

#### `sentinel policy validate` - Validate Policy File

```bash
sudo sentinel policy validate ./my-policy.yaml
```

#### `sentinel policy load` - Import External Policy

```bash
sudo sentinel policy load ./external-policy.yaml
```

#### `sentinel policy delete` - Delete Policy

```bash
sudo sentinel policy delete old-policy
sudo sentinel policy delete old-policy --force  # Skip confirmation
```

### Authorization Plugin Commands

#### `sentinel authz start` - Start Plugin Daemon

```bash
sudo sentinel authz start
sudo sentinel authz start --foreground  # For systemd
sudo sentinel authz start --policy strict --log-level debug
```

#### `sentinel authz stop` - Stop Plugin Daemon

```bash
sudo sentinel authz stop
```

#### `sentinel authz status` - Check Status

```bash
sudo sentinel authz status
```

#### `sentinel authz reload` - Reload Policy

```bash
sudo sentinel authz reload
```

#### `sentinel authz install` - Install in Docker

```bash
sudo sentinel authz install
sudo sentinel authz install --systemd --restart-docker
```

#### `sentinel authz uninstall` - Remove from Docker

```bash
sudo sentinel authz uninstall --systemd --restart-docker
```

---

## Policy System

### Policy Structure

```yaml
version: "1.0"
name: my-policy
description: "Custom security policy"
mode: enforce                   # enforce | warn | audit

settings:
  max_risk_score: 50
  require_image_scan: true
  image_scanning:
    enabled: true
    scanners: [trivy, grype]
    max_critical: 0
    max_high: 5
    cache_duration: 24h
  secret_scanning:
    enabled: true
    block_on_verified: true

rules:
  # Privileged mode
  privileged:
    action: block               # allow | warn | block
    message: "Privileged containers are not allowed"
    exceptions:
      - images: ["docker:dind"]
        reason: "Required for CI/CD"

  # Host namespace access
  host_namespaces:
    network:
      action: block
    pid:
      action: block
    ipc:
      action: warn
    uts:
      action: warn

  # Capabilities
  capabilities:
    default_action: warn
    require_drop_all: false
    blocked:
      - name: SYS_ADMIN
        message: "Grants near-root privileges"
      - name: SYS_PTRACE
      - name: NET_ADMIN
    allowed:
      - name: NET_BIND_SERVICE

  # Volume mounts
  mounts:
    block_bind_mounts: false
    blocked:
      - path: "/"
        message: "Host root access denied"
      - path: "/var/run/docker.sock"
        message: "Docker socket access denied"
      - path: "/proc"
      - path: "/sys"
    warned:
      - path: "/etc"
      - path: "/home"

  # Security options
  security_options:
    require_seccomp: false
    require_apparmor: false
    require_no_new_privileges: false

  # Container configuration
  container:
    require_non_root: false
    blocked_users: [root, "0"]
    require_read_only_rootfs: false
    require_resource_limits: false
    max_memory: "8Gi"
    max_cpus: "4"

  # Image rules
  images:
    allowed_registries:
      - docker.io
      - gcr.io
      - ghcr.io
      - quay.io
    block_latest_tag: false
    require_digest: false

  # Environment variables
  environment:
    block_secrets: true
    secret_patterns:
      - PASSWORD
      - TOKEN
      - API_KEY
      - SECRET

# Custom rules
custom_rules:
  - name: block-debug-images
    description: "Block debug images in production"
    severity: high
    condition:
      field: image
      operator: contains
      value: "debug"
    message: "Debug images not allowed"
```

### Built-in Policy Templates

| Template | Mode | Risk Score | Use Case |
|----------|------|------------|----------|
| `default` | warn | 50 | Balanced security with warnings |
| `strict` | enforce | 25 | Maximum security, zero tolerance |
| `permissive` | audit | 100 | Logging only, no blocking |
| `production` | enforce | 50 | Production workloads |
| `ci-cd` | enforce | 40 | CI/CD pipelines |

### Rule Actions

- **`allow`** - Permit the operation
- **`warn`** - Allow but log a warning
- **`block`** - Deny the operation

### Risk Categories

| Category | Description | Example |
|----------|-------------|---------|
| `privilege_escalation` | Gaining elevated privileges | `--privileged` |
| `container_escape` | Breaking container isolation | Host namespace access |
| `data_exposure` | Exposing sensitive data | Mounting `/etc/passwd` |
| `network_exposure` | Network misconfiguration | `--net=host` |
| `secret_exposure` | Exposed credentials | Passwords in env vars |
| `resource_abuse` | Uncontrolled resources | No memory limits |
| `supply_chain` | Image/artifact concerns | `:latest` tag |
| `misconfiguration` | Security misconfigurations | Disabled seccomp |

### Risk Score Impact

| Severity | Points |
|----------|--------|
| Critical | 40 |
| High | 25 |
| Medium | 15 |
| Low | 5 |

---

## Authorization Plugin

The authorization plugin provides daemon-level enforcement by intercepting all Docker API requests. Unlike CLI interception, this cannot be bypassed.

### How It Works

```
┌──────────────┐    ┌────────────────┐    ┌──────────────┐
│ Docker CLI   │───>│ Docker Daemon  │───>│   Sentinel   │
│ or API Call  │    │                │    │ AuthZ Plugin │
└──────────────┘    └────────────────┘    └──────────────┘
                            │                    │
                            │    Allow/Deny      │
                            │<───────────────────│
                            │
                            v
                    ┌──────────────┐
                    │   Execute    │
                    │   Command    │
                    └──────────────┘
```

### Setup

#### 1. Install Plugin in Docker

```bash
sudo sentinel authz install --systemd
```

This will:
- Update `/etc/docker/daemon.json` to add the authorization plugin
- Create plugin spec in `/etc/docker/plugins/sentinel.sock`
- Install systemd service (if `--systemd` flag used)

#### 2. Start the Plugin Daemon

```bash
# Using systemd (recommended for production)
sudo systemctl start docker-sentinel
sudo systemctl enable docker-sentinel

# Or manually
sudo sentinel authz start --foreground
```

#### 3. Restart Docker

```bash
sudo systemctl restart docker
```

#### 4. Verify Installation

```bash
sudo sentinel authz status
```

### Plugin Configuration

```bash
sudo sentinel authz start \
  --socket /run/docker/plugins/sentinel.sock \
  --policy strict \
  --fail-open=false \      # Deny on error (fail-closed)
  --hot-reload \           # Auto-reload on policy changes
  --hot-reload-debounce 500ms \
  --log-level info
```

### Hot Reload

The plugin automatically reloads policies when:
- Policy files are modified in the policies directory
- You run `sudo sentinel policy use <name>` to switch policies
- You run `sudo sentinel authz reload` manually
- The daemon receives a `SIGHUP` signal

### Uninstall

```bash
sudo sentinel authz uninstall --systemd --restart-docker
```

---

## Vulnerability Scanning

Sentinel integrates with multiple vulnerability scanners:

### Supported Scanners

| Scanner | Installation | Features |
|---------|--------------|----------|
| **Trivy** | `brew install trivy` | Fast, comprehensive, offline DB |
| **Grype** | `brew install grype` | Anchore's scanner, SBOM support |
| **Docker Scout** | Built into Docker Desktop | Native Docker integration |

### Usage

```bash
# Single scanner
sudo sentinel scan nginx:latest

# Multiple scanners
sudo sentinel scan --scanner trivy,grype myapp:v1.0

# With thresholds
sudo sentinel scan --fail-on --max-critical 0 --max-high 5 myapp:latest

# Filter severity
sudo sentinel scan --severity HIGH,CRITICAL myapp:latest
```

### Policy Integration

```yaml
settings:
  require_image_scan: true
  image_scanning:
    enabled: true
    scanners:
      - trivy
      - grype
    max_critical: 0
    max_high: 5
    cache_duration: 24h
```

---

## Secret Scanning

Sentinel uses TruffleHog to detect hardcoded secrets in container images.

### Usage

```bash
# Scan for secrets
sudo sentinel scan-secrets myapp:latest

# Fail if secrets found (CI/CD)
sudo sentinel scan-secrets --fail-on-secrets myapp:latest
```

### Automatic Scanning

Secrets are automatically scanned when using `sentinel exec`:

```bash
# Scans before push
sudo sentinel exec -- docker push myapp:latest

# Scans after build
sudo sentinel exec -- docker build -t myapp:latest .
```

### Detected Secret Types

- AWS credentials
- GCP service accounts
- GitHub tokens
- Stripe API keys
- Database connection strings
- SSH private keys
- Generic API keys and passwords

### Policy Configuration

```yaml
settings:
  secret_scanning:
    enabled: true
    block_on_verified: true  # Block verified (active) secrets
    max_critical: 0
    max_high: 0
    max_medium: 3
    ignore_detectors:        # Skip certain detectors
      - Mailchimp
    exclude_paths:           # Skip certain paths
      - /test/
```

---

## Examples

### Example 1: Development Environment

```bash
# Create permissive policy for development
sudo sentinel policy create dev-policy --template permissive
sudo sentinel policy use dev-policy

# Run containers with warnings only
sudo sentinel exec -- docker run -v /home:/home nginx
```

### Example 2: Production Environment

```bash
# Use strict policy
sudo sentinel policy use strict

# This will be blocked
sudo sentinel exec -- docker run --privileged ubuntu
# Error: Command blocked due to security policy violations

# This passes
sudo sentinel exec -- docker run --user 1000 -m 512m nginx:1.25.0
```

### Example 3: CI/CD Pipeline

```yaml
# .github/workflows/security.yml
jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Vulnerability Scan
        run: |
          sudo sentinel scan --fail-on --max-critical 0 myapp:${{ github.sha }}

      - name: Secret Scan
        run: |
          sudo sentinel scan-secrets --fail-on-secrets myapp:${{ github.sha }}

      - name: Validate Run Command
        run: |
          sudo sentinel validate -- docker run myapp:${{ github.sha }}
```

### Example 4: Custom Policy Rule

```yaml
# Block containers from running as root in production
custom_rules:
  - name: require-non-root
    description: "Containers must not run as root"
    severity: high
    category: privilege_escalation
    condition:
      or:
        - field: user
          operator: equals
          value: "root"
        - field: user
          operator: equals
          value: "0"
        - field: user
          operator: not_exists
    message: "Container must specify a non-root user with --user"
```

### Example 5: Enterprise Deployment

```bash
# 1. Install sentinel
sudo cp sentinel /usr/local/bin/

# 2. Create system config directory
sudo mkdir -p /etc/sentinel/policies

# 3. Deploy enterprise policy
sudo cp enterprise-policy.yaml /etc/sentinel/policies/

# 4. Install authorization plugin
sudo sentinel authz install --systemd

# 5. Start plugin
sudo systemctl enable docker-sentinel
sudo systemctl start docker-sentinel

# 6. Restart Docker
sudo systemctl restart docker

# 7. Verify
sudo sentinel authz status
```

---

## Troubleshooting

### For Users

#### My Docker Command Was Blocked

If your command was blocked, the error message explains why. Common solutions:

- **Privileged container blocked** - Remove `--privileged` flag, use specific capabilities instead
- **Dangerous mount blocked** - Avoid mounting sensitive paths like `/`, `/etc`, `/var/run/docker.sock`
- **Root user blocked** - Add `--user <uid>` to run as non-root
- **Latest tag blocked** - Use a specific image tag like `nginx:1.25` instead of `nginx:latest`

If you believe the command should be allowed, contact your system administrator.

#### I Can't Run `sentinel` Commands

Normal users cannot run `sentinel` commands - this is by design. Only administrators with root access can manage Sentinel. Contact your system administrator for policy changes.

---

### For Administrators

#### Plugin Not Starting

```bash
# Check status
sudo sentinel authz status

# View logs
journalctl -u docker-sentinel -f

# Check socket permissions
ls -la /run/docker/plugins/sentinel.sock
```

#### Docker Commands Failing

```bash
# Check if plugin is blocking
sudo sentinel authz status

# Temporarily use permissive mode
sudo sentinel policy use permissive
```

#### Policy Not Reloading

```bash
# Manually trigger reload
sudo sentinel authz reload

# Or send SIGHUP
sudo kill -HUP $(cat /var/run/sentinel-authz.pid)
```

#### Scanner Not Found

```bash
# Check scanner availability
which trivy
which grype

# Install missing scanner
brew install trivy  # macOS
apt install trivy   # Debian/Ubuntu
```

#### Permission Denied

```bash
# All Sentinel operations require root
sudo sentinel <command>

# If you see "sentinel requires root privileges", use sudo
sudo sentinel exec -- docker run nginx:latest
```

---

## Security Considerations

1. **User Separation** - Normal users cannot access Sentinel's CLI or configuration; they only see block messages when commands are denied
2. **Daemon-Level Enforcement** - The authorization plugin intercepts all Docker API calls and cannot be bypassed by users
3. **Root Required for Admin** - All administrative operations require root privileges
4. **Fail-Closed by Default** - The authorization plugin denies requests on error
5. **Policy Validation** - Policies are validated before activation
6. **Hot Reload Safety** - Debouncing prevents rapid policy changes
7. **Least Privilege** - Start with strict policy, add exceptions as needed

---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

---

## License

MIT License - See [LICENSE](LICENSE) for details.
