# Docker Sentinel Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Docker Sentinel.

## Quick Diagnostics

Before diving into specific issues, run the built-in diagnostics:

```bash
sudo sentinel doctor
```

This checks Docker connectivity, configuration, policies, and scanner availability.

---

## Common Issues

### "sentinel requires root privileges"

**Symptom:** Error message when running any sentinel command.

**Cause:** Sentinel requires root access to interact with Docker and manage system-wide policies.

**Solution:**
```bash
# Run with sudo
sudo sentinel <command>

# Or (not recommended) add your user to the docker group
sudo usermod -aG docker $USER
# Then log out and back in
```

---

### "Docker daemon is not running"

**Symptom:** `sentinel doctor` shows Docker daemon as not running.

**Solutions:**

```bash
# Check Docker status
systemctl status docker

# Start Docker if stopped
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# If Docker Desktop (macOS/Windows), ensure the application is running
```

---

### "Permission denied" when accessing Docker

**Symptom:** Sentinel can't communicate with Docker socket.

**Cause:** Socket permissions or SELinux/AppArmor restrictions.

**Solutions:**

```bash
# Check Docker socket permissions
ls -la /var/run/docker.sock

# Fix permissions (temporary)
sudo chmod 666 /var/run/docker.sock

# Better: Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# If SELinux is blocking:
sudo setenforce 0  # Temporary disable
# Or create proper SELinux policy
```

---

### "No policy files found"

**Symptom:** Sentinel can't find policies or uses default policy.

**Solutions:**

```bash
# Initialize policies
sudo sentinel init

# Or manually create policies directory
sudo mkdir -p /etc/sentinel/policies

# Create default policy
sudo sentinel policy create default --template default

# Set active policy
sudo sentinel policy use default
```

---

### "Policy cannot be loaded"

**Symptom:** Error when loading a policy file.

**Cause:** YAML syntax error or invalid policy structure.

**Solutions:**

```bash
# Validate policy syntax
sudo sentinel policy validate /etc/sentinel/policies/my-policy.yaml

# Check YAML syntax
yamllint /etc/sentinel/policies/my-policy.yaml

# View the policy for obvious errors
cat /etc/sentinel/policies/my-policy.yaml

# Start fresh with a template
sudo sentinel policy create my-policy --template default
```

---

### Scanners not working

#### "Trivy is not installed"

```bash
# macOS
brew install trivy

# Linux (Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Verify
trivy version
```

#### "Grype is not installed"

```bash
# macOS
brew install grype

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Verify
grype version
```

#### "TruffleHog is not installed"

```bash
# macOS
brew install trufflehog

# Linux (using Go)
go install github.com/trufflesecurity/trufflehog/v3@latest

# Or download binary
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Verify
trufflehog --version
```

---

### Authorization Plugin Issues

#### "Authorization plugin is not running"

```bash
# Check status
sudo sentinel authz status

# Start the plugin
sudo sentinel authz start

# Or install as systemd service
sudo sentinel authz install --systemd --restart-docker
```

#### "Plugin crashes or Docker won't start"

If the authorization plugin causes Docker to fail:

```bash
# Emergency: Disable the plugin
sudo systemctl stop docker-sentinel
sudo rm /etc/docker/daemon.json.d/sentinel.json  # If exists

# Remove plugin from Docker config
sudo nano /etc/docker/daemon.json
# Remove the "authorization-plugins" section

# Restart Docker
sudo systemctl restart docker

# Investigate logs
sudo journalctl -u docker-sentinel -n 100
```

#### "Docker commands hang"

**Cause:** Plugin socket not responding.

```bash
# Check if plugin socket exists
ls -la /var/run/sentinel-authz.sock

# Restart the plugin
sudo sentinel authz reload

# If that fails, restart completely
sudo sentinel authz stop
sudo sentinel authz start

# Check plugin logs
sudo journalctl -u docker-sentinel --since "10 minutes ago"
```

---

### Configuration Issues

#### "Configuration not loaded"

```bash
# Check config file location
ls -la /etc/sentinel/config.yaml
ls -la ~/.sentinel/config.yaml

# Create default config
sudo sentinel init --no-interactive

# Or manually create
sudo mkdir -p /etc/sentinel
sudo cat > /etc/sentinel/config.yaml << 'EOF'
version: "1.0"
mode: enforce
active_policy: default
global_settings:
  max_risk_score: 50
EOF
```

#### "Active policy not set"

```bash
# List available policies
sudo sentinel policy list

# Set active policy
sudo sentinel policy use default

# Verify
sudo sentinel policy show
```

---

### Scan Issues

#### "Image not found"

```bash
# Ensure image exists locally
docker images | grep <image-name>

# Pull if needed
docker pull <image-name>

# Then scan
sudo sentinel scan <image-name>
```

#### "Scan timeout"

For large images, scanning may take a long time.

```bash
# Increase timeout (if available in future versions)
# For now, ensure the image is pulled before scanning

# Pull image first
docker pull large-image:latest

# Then scan (caches will be populated)
sudo sentinel scan large-image:latest
```

---

### Audit Issues

#### "No audit entries found"

```bash
# Check audit directory
ls -la /etc/sentinel/audit/

# Ensure audit is enabled in policy
sudo sentinel policy show | grep -i audit

# Run a command to generate audit entry
sudo sentinel validate -- docker run hello-world
sudo sentinel audit list --limit 10
```

#### "Cannot read audit database"

```bash
# Check permissions
ls -la /etc/sentinel/audit/audit.db

# Fix permissions
sudo chown root:root /etc/sentinel/audit/audit.db
sudo chmod 644 /etc/sentinel/audit/audit.db

# If corrupted, backup and recreate
sudo mv /etc/sentinel/audit/audit.db /etc/sentinel/audit/audit.db.bak
# New database will be created on next audit write
```

---

## Getting Help

### Collect Diagnostic Information

When reporting issues, include:

```bash
# Version info
sentinel version

# Doctor output
sudo sentinel doctor

# Configuration
sudo sentinel policy show

# System info
uname -a
docker version
```

### Log Locations

- **Sentinel Daemon**: `journalctl -u docker-sentinel`
- **Docker Daemon**: `journalctl -u docker`
- **Audit Logs**: `/etc/sentinel/audit/audit.jsonl`

### Report Issues

- GitHub Issues: https://github.com/rtvkiz/docker-sentinel/issues
- Include diagnostic output and steps to reproduce

---

## Emergency Recovery

If Sentinel is blocking all Docker commands and you need to recover:

```bash
# 1. Stop the authorization plugin
sudo systemctl stop docker-sentinel 2>/dev/null || true
sudo pkill -f sentinel-authz 2>/dev/null || true

# 2. Remove plugin from Docker config
sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak
sudo jq 'del(."authorization-plugins")' /etc/docker/daemon.json > /tmp/daemon.json
sudo mv /tmp/daemon.json /etc/docker/daemon.json

# 3. Restart Docker
sudo systemctl restart docker

# 4. Verify Docker works
docker ps

# 5. Switch to permissive mode before re-enabling
sudo sentinel policy use permissive
sudo sentinel authz start
```
