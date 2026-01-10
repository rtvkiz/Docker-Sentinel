---
name: container-security
description: Pre-runtime container security analysis. Reviews Dockerfiles, docker-compose files, and container images for security vulnerabilities before deployment. Use when analyzing Dockerfiles, scanning images for CVEs, reviewing container configurations, or when the user mentions container security, Docker security, or image scanning.
allowed-tools: Read, Grep, Glob, Bash
---

# Container Security Analysis

Perform comprehensive pre-runtime security analysis on container configurations and images.

## Scope

This skill focuses on **pre-runtime** security - identifying issues before containers are deployed:
- Dockerfile security review
- Base image vulnerability assessment
- Docker Compose configuration analysis
- Secret and credential detection
- Image scanning with external tools

## Dockerfile Security Review

When analyzing a Dockerfile, check for these issues:

### Critical Issues
1. **Running as root**: No `USER` instruction or explicitly using `USER root`
2. **Hardcoded secrets**: API keys, passwords, tokens in ENV or ARG
3. **Untrusted base images**: Using `latest` tag or unverified publishers
4. **Privileged instructions**: `--privileged`, `--cap-add=ALL`

### High Severity
1. **Outdated base images**: Known CVEs in base image
2. **Exposed sensitive ports**: Unnecessary `EXPOSE` directives
3. **Writable root filesystem**: No `--read-only` consideration
4. **Missing health checks**: No `HEALTHCHECK` instruction
5. **Package manager cache**: Not cleaning apt/yum cache after install

### Medium Severity
1. **No pinned versions**: Using `apt install package` without version
2. **Multiple RUN layers**: Not consolidating commands
3. **ADD vs COPY**: Using ADD when COPY suffices
4. **Missing .dockerignore**: Potential secret leakage in build context

### Security Checklist Template

```markdown
## Dockerfile Security Report

### File: [filename]

| Check | Status | Details |
|-------|--------|---------|
| Non-root user | | |
| Pinned base image | | |
| No hardcoded secrets | | |
| Minimal base image | | |
| Package versions pinned | | |
| Cache cleaned | | |
| HEALTHCHECK present | | |
| .dockerignore exists | | |
```

## Docker Compose Security Review

Check docker-compose.yml files for:

1. **Privileged mode**: `privileged: true`
2. **Dangerous capabilities**: `cap_add` without `cap_drop`
3. **Host network mode**: `network_mode: host`
4. **Sensitive volume mounts**: `/var/run/docker.sock`, `/etc`, `/root`
5. **Environment secrets**: Plaintext secrets in `environment:`
6. **No resource limits**: Missing `deploy.resources.limits`
7. **Host PID/IPC**: `pid: host` or `ipc: host`

## Image Scanning Integration

### Trivy

```bash
# Scan a local image
trivy image <image-name>

# Scan with severity filter
trivy image --severity HIGH,CRITICAL <image-name>

# Scan Dockerfile
trivy config Dockerfile

# Output as JSON for parsing
trivy image --format json --output results.json <image-name>

# Scan and fail on critical vulnerabilities
trivy image --exit-code 1 --severity CRITICAL <image-name>
```

### Grype & Syft

```bash
# Generate SBOM with Syft
syft <image-name> -o json > sbom.json

# Scan image with Grype
grype <image-name>

# Scan from SBOM
grype sbom:sbom.json

# Filter by severity
grype <image-name> --only-fixed --fail-on high
```

### Docker Scout

```bash
# Quick vulnerability overview
docker scout quickview <image-name>

# Detailed CVE list
docker scout cves <image-name>

# Recommendations for base image
docker scout recommendations <image-name>

# Compare images
docker scout compare <image1> <image2>
```

## Analysis Workflow

When asked to analyze container security:

1. **Identify targets**: Find Dockerfiles, docker-compose files, and image references
   ```bash
   find . -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "*.dockerfile"
   ```

2. **Static analysis**: Review configurations against security checklist

3. **Tool-based scanning**: If scanners are available, run them:
   - Check tool availability: `which trivy grype docker`
   - Run appropriate scanner on images/files

4. **Generate report**: Summarize findings by severity with remediation steps

## Remediation Guidance

### Non-root User
```dockerfile
# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
USER appuser
```

### Pinned Base Image
```dockerfile
# Use specific digest
FROM python:3.11-slim@sha256:abc123...

# Or specific version tag
FROM python:3.11.7-slim-bookworm
```

### Secret Management
```dockerfile
# DON'T: Hardcode secrets
ENV API_KEY=secret123

# DO: Use build-time secrets (BuildKit)
RUN --mount=type=secret,id=api_key cat /run/secrets/api_key

# DO: Use runtime environment variables or secret managers
```

### Minimal Base Images
Prefer in order:
1. `distroless` - Google's minimal images
2. `alpine` - Minimal Linux (~5MB)
3. `*-slim` variants - Reduced Debian/Ubuntu

### Resource Limits (Compose)
```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          memory: 256M
```

## Output Format

Always provide findings in this structure:

```markdown
# Container Security Analysis

## Summary
- Critical: X
- High: X
- Medium: X
- Low: X

## Critical Findings
[List with file location and remediation]

## High Findings
[List with file location and remediation]

## Recommendations
[Prioritized list of actions]
```
