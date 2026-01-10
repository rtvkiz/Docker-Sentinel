# Docker Sentinel - Requirements & Setup

## System Requirements

- **OS**: Linux, macOS, or Windows (WSL2)
- **Go**: 1.21+ (for building from source)
- **Docker**: 20.10+ (required for container operations)

## Required Dependencies

### Core (Required)

| Tool | Purpose | Installation |
|------|---------|--------------|
| Docker | Container runtime | [Install Docker](https://docs.docker.com/get-docker/) |

### Vulnerability Scanners (At least one recommended)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Trivy** | CVE scanning | `brew install trivy` or [aquasecurity/trivy](https://github.com/aquasecurity/trivy#installation) |
| Grype | CVE scanning | `brew install grype` or [anchore/grype](https://github.com/anchore/grype#installation) |
| Docker Scout | CVE scanning | Built into Docker Desktop, or `docker scout` CLI |

### Secret Scanning (Recommended)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **TruffleHog** | Secret detection in images | See below |

## Installation Guide

### 1. Install Docker Sentinel

```bash
# Clone the repository
git clone https://github.com/rtvkiz/docker-sentinel.git
cd docker-sentinel

# Build
make build

# Install to PATH
sudo cp bin/sentinel /usr/local/bin/
# or for user-local install:
mkdir -p ~/.local/bin
cp bin/sentinel ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

### 2. Install Trivy (Vulnerability Scanner)

**macOS:**
```bash
brew install trivy
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**Linux (RHEL/CentOS):**
```bash
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.rpm
```

**Docker:**
```bash
docker pull aquasec/trivy
alias trivy="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy"
```

### 3. Install TruffleHog (Secret Scanner)

**macOS:**
```bash
brew install trufflehog
```

**Linux/macOS (pip):**
```bash
pip install trufflehog
```

**Linux/macOS (binary):**
```bash
# Download latest release from https://github.com/trufflesecurity/trufflehog/releases
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

**Docker:**
```bash
docker pull trufflesecurity/trufflehog
alias trufflehog="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock trufflesecurity/trufflehog"
```

### 4. Install Grype (Optional - Alternative CVE Scanner)

**macOS:**
```bash
brew install grype
```

**Linux:**
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### 5. Initialize Sentinel

```bash
# Initialize policies and configuration
sentinel policy init

# Verify installation
sentinel --version
sentinel policy list
```

### 6. Set Up Docker Interception (Optional)

To automatically validate all docker commands:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias docker='sentinel exec --'

# Reload shell
source ~/.bashrc  # or ~/.zshrc
```

## Verification

Run these commands to verify your setup:

```bash
# Check Sentinel
sentinel --version

# Check Trivy
trivy --version

# Check TruffleHog
trufflehog --version

# Check Grype (optional)
grype version

# Test validation
sentinel validate -- run --privileged nginx

# Test vulnerability scanning
sentinel scan nginx:latest

# Test secret scanning
sentinel scan-secrets nginx:latest
```

## Configuration

Sentinel stores configuration in `~/.sentinel/`:

```
~/.sentinel/
├── config.yaml       # Main configuration
├── audit.db          # SQLite audit database
├── policies/         # Security policies
│   ├── default.yaml
│   ├── strict.yaml
│   └── permissive.yaml
└── rego/             # OPA/Rego policies
    ├── privileged.rego
    ├── mounts.rego
    └── capabilities.rego
```

### Minimal config.yaml

```yaml
version: "1.0"
mode: warn                    # enforce, warn, or audit
active_policy: default

global_settings:
  max_risk_score: 50
  require_image_scan: false

image_scanning:
  enabled: true
  scanners:
    - trivy
  max_critical: 0
  max_high: 5

audit:
  enabled: true
  log_all_commands: true
```

## Recommended Setup for Different Environments

### Development

```bash
sentinel policy set permissive
# or
sentinel policy set default
```

### CI/CD Pipelines

```yaml
# .github/workflows/docker-security.yml
- name: Install Sentinel
  run: |
    curl -sSL https://get.docker-sentinel.dev | sh
    sentinel policy init

- name: Build Image
  run: docker build -t myapp:${{ github.sha }} .

- name: Scan for Vulnerabilities
  run: sentinel scan --fail-on myapp:${{ github.sha }}

- name: Scan for Secrets
  run: sentinel scan-secrets --fail-on-secrets myapp:${{ github.sha }}
```

### Production

```bash
sentinel policy set strict
# Blocks all dangerous operations
```

## Troubleshooting

### "command not found: sentinel"

Add to your PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### "trivy is not installed"

Install Trivy:
```bash
brew install trivy
```

### "trufflehog is not installed"

Install TruffleHog:
```bash
brew install trufflehog
# or
pip install trufflehog
```

### Scanning is slow

Enable caching:
```yaml
# ~/.sentinel/config.yaml
image_scanning:
  cache_duration: "24h"
```

### Docker socket permission denied

```bash
sudo usermod -aG docker $USER
# Then log out and log back in
```

## Quick Reference

```bash
# Validate a command
sentinel validate -- run --privileged nginx

# Execute with validation
sentinel exec -- run -d nginx

# Scan for CVEs
sentinel scan nginx:latest

# Scan for secrets
sentinel scan-secrets myapp:latest

# View audit logs
sentinel audit logs

# Manage policies
sentinel policy list
sentinel policy set strict
sentinel policy show
```
