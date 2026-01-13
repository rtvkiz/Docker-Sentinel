# Docker Sentinel

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-20.10+-2496ED?logo=docker&logoColor=white)

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
- **Secret Detection** - Find hardcoded secrets with TruffleHog
- **Hot Reload** - Policy changes apply automatically without restart
- **Risk Scoring** - Quantified risk assessment (0-100) for each command

---

## Quick Start

### Install

```bash
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash
```

### Verify

```bash
sudo sentinel authz status
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

### Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/uninstall.sh | sudo bash
```

---

## Installation

### Prerequisites

- Docker 20.10+
- Root/sudo access
- Go 1.21+ (only for building from source)

### Optional Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| Trivy | CVE scanning | `brew install trivy` |
| Grype | CVE scanning | `brew install grype` |
| TruffleHog | Secret detection | `brew install trufflehog` |

### Build from Source

```bash
git clone https://github.com/rtvkiz/docker-sentinel.git
cd docker-sentinel
go build -o sentinel ./cmd/sentinel
sudo mv sentinel /usr/local/bin/
sudo sentinel authz install --systemd --restart-docker
```

### Deployment Options

**Authorization Plugin (Recommended)** - Daemon-level, cannot be bypassed:
```bash
sudo sentinel authz install --systemd --restart-docker
```

**Shell Integration** - For development/testing only:
```bash
sudo sentinel install --method alias --shell bash
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
└── cache/               # Scan result cache
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINEL_CONFIG_DIR` | Config directory | `/etc/sentinel` |
| `EDITOR` | Editor for `policy edit` | `vim` |

---

## CLI Commands

> All commands require root privileges (`sudo`).

### Validation

```bash
# Execute with security checks
sudo sentinel exec -- docker run nginx:latest

# Validate without executing
sudo sentinel validate -- docker run --privileged ubuntu
```

### Scanning

```bash
# Vulnerability scan
sudo sentinel scan nginx:latest
sudo sentinel scan --scanner trivy,grype --fail-on --max-critical 0 myapp:latest

# Secret scan
sudo sentinel scan-secrets myapp:latest
sudo sentinel scan-secrets --fail-on-secrets myapp:latest
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
sudo sentinel authz install --systemd  # Install in Docker
sudo sentinel authz uninstall          # Remove from Docker
```

---

## Policy System

### Example Policy

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
    scanners: [trivy]
    max_critical: 0
    max_high: 5
  secret_scanning:
    enabled: true
    block_on_verified: true

rules:
  privileged:
    action: block
    exceptions:
      - images: ["docker:dind"]

  host_namespaces:
    network: { action: block }
    pid: { action: block }
    ipc: { action: warn }

  capabilities:
    blocked:
      - name: SYS_ADMIN
      - name: SYS_PTRACE
      - name: NET_ADMIN

  mounts:
    blocked:
      - path: "/"
      - path: "/var/run/docker.sock"
    warned:
      - path: "/etc"
      - path: "/home"

  security_options:
    require_seccomp: false
    require_apparmor: false

  container:
    require_non_root: false
    require_resource_limits: false

  images:
    allowed_registries: [docker.io, gcr.io, ghcr.io]
    block_latest_tag: false

  environment:
    block_secrets: true
    secret_patterns: [PASSWORD, TOKEN, API_KEY]
```

### Built-in Templates

| Template | Mode | Risk Score | Use Case |
|----------|------|------------|----------|
| `default` | warn | 50 | Balanced security |
| `strict` | enforce | 25 | Maximum security |
| `permissive` | audit | 100 | Logging only |
| `production` | enforce | 50 | Production workloads |
| `ci-cd` | enforce | 40 | CI/CD pipelines |

### Risk Scoring

| Severity | Points |
|----------|--------|
| Critical | 40 |
| High | 25 |
| Medium | 15 |
| Low | 5 |

---

## Examples

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: docker build -t myapp:${{ github.sha }} .

      - name: Vulnerability Scan
        run: sudo sentinel scan --fail-on --max-critical 0 myapp:${{ github.sha }}

      - name: Secret Scan
        run: sudo sentinel scan-secrets --fail-on-secrets myapp:${{ github.sha }}
```

### Custom Rule

```yaml
custom_rules:
  - name: require-non-root
    severity: high
    condition:
      field: user
      operator: equals
      value: "root"
    message: "Container must specify a non-root user"
```

---

## Troubleshooting

### Plugin Not Starting

```bash
sudo sentinel authz status
journalctl -u docker-sentinel -f
```

### Docker Commands Failing

```bash
# Use permissive mode temporarily
sudo sentinel policy use permissive
```

### Policy Not Reloading

```bash
sudo sentinel authz reload
# or
sudo kill -HUP $(cat /var/run/sentinel-authz.pid)
```

---

## Security Considerations

1. **Daemon-Level Enforcement** - Cannot be bypassed by users
2. **Root Required** - All admin operations require root
3. **Fail-Closed** - Denies requests on error by default
4. **Hot Reload Safety** - Debouncing prevents rapid policy changes

---

## License

MIT License - See [LICENSE](LICENSE) for details.
