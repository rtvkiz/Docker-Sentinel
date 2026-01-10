# Docker Sentinel - Design Document

## Overview

Docker Sentinel is a pre-runtime container security tool that intercepts Docker commands before execution, validates them against security policies, and blocks or warns about dangerous operations.

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER                                    │
│                           │                                     │
│                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  $ docker run --privileged -v /:/host nginx             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│                     (intercepted)                               │
│                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              DOCKER SENTINEL                             │   │
│  │                                                          │   │
│  │   ┌──────────┐   ┌──────────┐   ┌──────────────────┐    │   │
│  │   │  Parser  │──▶│  Rules   │──▶│  Decision Engine │    │   │
│  │   └──────────┘   │  Engine  │   └──────────────────┘    │   │
│  │        │         └──────────┘            │              │   │
│  │        │              │                  │              │   │
│  │        ▼              ▼                  ▼              │   │
│  │   ┌──────────┐   ┌──────────┐   ┌──────────────────┐    │   │
│  │   │ Command  │   │  Policy  │   │ ALLOW / BLOCK /  │    │   │
│  │   │  Struct  │   │  Config  │   │     WARN         │    │   │
│  │   └──────────┘   └──────────┘   └──────────────────┘    │   │
│  │                                          │              │   │
│  └──────────────────────────────────────────│──────────────┘   │
│                                             │                   │
│                    ┌────────────────────────┴───────┐           │
│                    ▼                                ▼           │
│              ┌──────────┐                    ┌──────────┐       │
│              │  BLOCK   │                    │  ALLOW   │       │
│              │  (exit)  │                    │ (execute)│       │
│              └──────────┘                    └────┬─────┘       │
│                                                   │             │
│                                                   ▼             │
│                                          ┌──────────────┐       │
│                                          │ Docker CLI   │       │
│                                          └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Command Parser (`pkg/interceptor/`)

The parser converts raw Docker CLI arguments into a structured `DockerCommand` object.

```
INPUT:  ["run", "--privileged", "-v", "/:/host", "-e", "SECRET=abc", "nginx:latest"]
                                    │
                                    ▼
                            ┌───────────────┐
                            │    PARSER     │
                            └───────────────┘
                                    │
                                    ▼
OUTPUT: DockerCommand{
            Action:      "run"
            Image:       "nginx:latest"
            Privileged:  true
            Volumes:     [{Source: "/", Destination: "/host"}]
            Environment: [{Key: "SECRET", Value: "abc", IsSecret: true}]
        }
```

**Key files:**
- `parser.go` - Parses CLI arguments for run, exec, build commands
- `types.go` - Defines DockerCommand struct and dangerous patterns

**What it extracts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    DockerCommand                            │
├─────────────────────────────────────────────────────────────┤
│  Action         │ run, exec, build, pull, etc.              │
│  Image          │ nginx:latest, ubuntu:22.04                │
│  Privileged     │ true/false (--privileged)                 │
│  User           │ root, 1000, nobody                        │
│  NetworkMode    │ host, bridge, none                        │
│  PIDMode        │ host, container:xxx                       │
│  Capabilities   │ {Add: [SYS_ADMIN], Drop: [ALL]}           │
│  Volumes        │ [{Source, Destination, ReadOnly}]         │
│  SecurityOpts   │ [{Type: seccomp, Value: unconfined}]      │
│  Environment    │ [{Key, Value, IsSecret}]                  │
│  Resources      │ {Memory, CPUs}                            │
└─────────────────────────────────────────────────────────────┘
```

---

### 2. Policy System (`pkg/policy/`)

Policies define what's allowed, warned, or blocked.

```
┌─────────────────────────────────────────────────────────────┐
│                      POLICY STRUCTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ METADATA                                             │   │
│  │   name: production                                   │   │
│  │   mode: enforce  ◄─── enforce | warn | audit         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SETTINGS                                             │   │
│  │   max_risk_score: 25                                 │   │
│  │   require_image_scan: true                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ RULES                                                │   │
│  │                                                      │   │
│  │   privileged: {action: block}                        │   │
│  │   host_namespaces:                                   │   │
│  │     network: {action: block}                         │   │
│  │     pid: {action: block}                             │   │
│  │   capabilities:                                      │   │
│  │     blocked: [SYS_ADMIN, SYS_PTRACE]                │   │
│  │   mounts:                                            │   │
│  │     blocked: [/, /var/run/docker.sock]              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ CUSTOM RULES (optional)                              │   │
│  │   - name: no-debug-images                            │   │
│  │     condition: {field: image, operator: matches,     │   │
│  │                 value: ".*debug.*"}                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ REGO POLICIES (optional - OPA integration)           │   │
│  │   package docker.security                            │   │
│  │   deny[msg] { input.privileged == true }            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Policy Modes:**
```
┌──────────┬────────────────────────────────────────────────────┐
│  MODE    │  BEHAVIOR                                          │
├──────────┼────────────────────────────────────────────────────┤
│ enforce  │  Block commands that violate policy                │
│ warn     │  Show warnings but allow execution                 │
│ audit    │  Log everything, never block                       │
└──────────┴────────────────────────────────────────────────────┘
```

**Key files:**
- `types.go` - Policy structure definition
- `manager.go` - Load, save, list, validate policies
- `evaluator.go` - Evaluate commands against policies
- `opa.go` - OPA/Rego integration for advanced rules

---

### 3. Rules Engine (`pkg/rules/`)

The rules engine contains built-in security checks and evaluates commands.

```
┌─────────────────────────────────────────────────────────────┐
│                    RULES ENGINE                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   DockerCommand ──────┐                                     │
│                       ▼                                     │
│            ┌──────────────────┐                             │
│            │  RULE EVALUATOR  │                             │
│            └────────┬─────────┘                             │
│                     │                                       │
│        ┌────────────┼────────────┐                          │
│        ▼            ▼            ▼                          │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                     │
│   │ Rule 1  │  │ Rule 2  │  │ Rule N  │                     │
│   │Privilege│  │HostPID  │  │ Mounts  │                     │
│   └────┬────┘  └────┬────┘  └────┬────┘                     │
│        │            │            │                          │
│        └────────────┴────────────┘                          │
│                     │                                       │
│                     ▼                                       │
│            ┌──────────────────┐                             │
│            │ ValidationResult │                             │
│            │   - Allowed      │                             │
│            │   - Score: 85    │                             │
│            │   - Risks: [...]  │                             │
│            │   - Warnings: [..]│                             │
│            └──────────────────┘                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Built-in Rules:**

| Rule | Severity | What it Detects |
|------|----------|-----------------|
| `privileged_container` | CRITICAL | `--privileged` flag |
| `host_pid` | CRITICAL | `--pid=host` |
| `host_network` | HIGH | `--network=host` |
| `docker_socket_mount` | CRITICAL | Mounting `/var/run/docker.sock` |
| `root_filesystem_mount` | CRITICAL | Mounting `/` |
| `dangerous_capabilities` | CRITICAL | `SYS_ADMIN`, `SYS_PTRACE`, etc. |
| `sensitive_mounts` | HIGH | `/etc`, `/proc`, `/sys` |
| `disabled_seccomp` | HIGH | `seccomp=unconfined` |
| `disabled_apparmor` | HIGH | `apparmor=unconfined` |
| `secret_in_env` | MEDIUM | Passwords in environment |
| `latest_tag` | LOW | Using `:latest` tag |
| `no_user` | MEDIUM | Running as root |
| `untrusted_registry` | MEDIUM | Non-allowlisted registry |

**Risk Scoring:**
```
┌────────────┬───────────────┐
│  SEVERITY  │  SCORE IMPACT │
├────────────┼───────────────┤
│  CRITICAL  │      +40      │
│  HIGH      │      +25      │
│  MEDIUM    │      +15      │
│  LOW       │      +5       │
└────────────┴───────────────┘

Total Score = Sum of all triggered rule scores (capped at 100)
```

---

### 4. Scanner Integration (`pkg/scanner/`)

Optional integration with vulnerability scanners for image analysis.

```
┌─────────────────────────────────────────────────────────────┐
│                   IMAGE SCANNING                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Image: nginx:latest                                       │
│              │                                              │
│              ▼                                              │
│   ┌──────────────────────────────────────────────┐         │
│   │              SCANNER INTERFACE               │         │
│   └──────────────────────────────────────────────┘         │
│              │                                              │
│   ┌──────────┴──────────┬──────────────┐                   │
│   ▼                     ▼              ▼                   │
│ ┌──────────┐      ┌──────────┐   ┌──────────────┐          │
│ │  TRIVY   │      │  GRYPE   │   │ DOCKER SCOUT │          │
│ └────┬─────┘      └────┬─────┘   └──────┬───────┘          │
│      │                 │                │                  │
│      └─────────────────┴────────────────┘                  │
│                        │                                    │
│                        ▼                                    │
│              ┌──────────────────┐                          │
│              │   ScanResult     │                          │
│              │  Critical: 2     │                          │
│              │  High: 5         │                          │
│              │  Medium: 12      │                          │
│              │  CVE-2024-xxxx   │                          │
│              └──────────────────┘                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Execution Flow

### Flow 1: `sentinel validate -- run --privileged nginx`

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  1. PARSE ARGUMENTS                                            │
│     └─▶ Extract: Action=run, Privileged=true, Image=nginx     │
│                                                                │
│  2. LOAD POLICY                                                │
│     └─▶ Load active policy from ~/.sentinel/policies/         │
│                                                                │
│  3. EVALUATE RULES                                             │
│     └─▶ Check each rule against DockerCommand                  │
│         ├─▶ privileged_container: FAIL (score +40)             │
│         ├─▶ latest_tag: FAIL (score +5)                        │
│         └─▶ no_user: FAIL (score +15)                          │
│                                                                │
│  4. CALCULATE RESULT                                           │
│     └─▶ Score: 60, Risks: 3, Allowed: false                   │
│                                                                │
│  5. OUTPUT RESULT                                              │
│     └─▶ Print risks, mitigations, exit code 1                 │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Flow 2: `sentinel exec -- run nginx:1.25`

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  1. PARSE ARGUMENTS                                            │
│     └─▶ Extract: Action=run, Image=nginx:1.25                 │
│                                                                │
│  2. LOAD POLICY                                                │
│     └─▶ Load active policy                                     │
│                                                                │
│  3. EVALUATE RULES                                             │
│     └─▶ All rules pass                                         │
│                                                                │
│  4. CALCULATE RESULT                                           │
│     └─▶ Score: 0, Risks: 0, Allowed: true                     │
│                                                                │
│  5. LOG TO AUDIT                                               │
│     └─▶ Write event to ~/.sentinel/audit.db                   │
│                                                                │
│  6. EXECUTE DOCKER                                             │
│     └─▶ exec.Command("docker", "run", "nginx:1.25")           │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
docker-sentinel/
│
├── cmd/sentinel/              # CLI entry point
│   ├── main.go               # Command definitions
│   ├── commands.go           # exec, validate, scan, install
│   └── policy_commands.go    # policy subcommands
│
├── pkg/
│   ├── interceptor/          # Docker command parser
│   │   ├── types.go         # DockerCommand struct
│   │   └── parser.go        # CLI argument parser
│   │
│   ├── rules/                # Built-in security rules
│   │   ├── types.go         # Rule interface, risk types
│   │   ├── engine.go        # Rule evaluation engine
│   │   └── builtin.go       # 15 built-in rules
│   │
│   ├── policy/               # Policy management
│   │   ├── types.go         # Policy structure
│   │   ├── manager.go       # CRUD operations
│   │   ├── evaluator.go     # Policy evaluation
│   │   └── opa.go           # OPA/Rego integration
│   │
│   ├── scanner/              # Vulnerability scanners
│   │   ├── types.go         # Scanner interface
│   │   ├── trivy.go         # Trivy integration
│   │   ├── grype.go         # Grype integration
│   │   └── scout.go         # Docker Scout integration
│   │
│   ├── audit/                # Audit logging
│   │   ├── logger.go        # SQLite-based logger
│   │   └── reporter.go      # Report generation
│   │
│   └── config/               # Configuration
│       └── config.go        # Config loading/saving
│
├── configs/policies/         # Example policies
│   ├── default.yaml
│   ├── strict.yaml
│   ├── development.yaml
│   ├── production.yaml
│   └── ci-cd.yaml
│
└── docs/
    └── DESIGN.md            # This document
```

---

## Installation Modes

```
┌─────────────────────────────────────────────────────────────┐
│                   INSTALLATION OPTIONS                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  METHOD 1: Shell Alias (Recommended)                        │
│  ────────────────────────────────────                       │
│  alias docker='sentinel exec --'                            │
│                                                             │
│  User types: docker run nginx                               │
│  Actual:     sentinel exec -- run nginx                     │
│                                                             │
│                                                             │
│  METHOD 2: PATH Wrapper                                     │
│  ────────────────────────                                   │
│  /usr/bin/docker → /usr/bin/docker-real                    │
│  /usr/bin/docker → symlink to sentinel                     │
│                                                             │
│  Sentinel calls docker-real after validation                │
│                                                             │
│                                                             │
│  METHOD 3: Direct Validation                                │
│  ──────────────────────────                                 │
│  sentinel validate -- run --privileged nginx                │
│  (Validate without executing)                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Storage

```
~/.sentinel/
├── config.yaml          # Main configuration
├── audit.db             # SQLite audit database
├── policies/            # Policy files
│   ├── default.yaml
│   ├── strict.yaml
│   └── custom.yaml
├── rego/                # OPA/Rego policies
│   ├── privileged.rego
│   ├── mounts.rego
│   └── capabilities.rego
└── cache/               # Scanner cache
    └── image-scans.db
```

---

## Example: How a Dangerous Command Gets Blocked

```
$ sentinel validate -- run --privileged -v /var/run/docker.sock:/var/run/docker.sock ubuntu

┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Parse Command                                       │
│                                                             │
│   DockerCommand {                                           │
│     Action: "run"                                           │
│     Privileged: true          ◄── DANGEROUS                 │
│     Volumes: [                                              │
│       {Source: "/var/run/docker.sock",                      │
│        Destination: "/var/run/docker.sock"}  ◄── DANGEROUS  │
│     ]                                                       │
│     Image: "ubuntu"           ◄── No tag (defaults :latest)│
│   }                                                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: Evaluate Against Rules                              │
│                                                             │
│   [CRITICAL] privileged_container                           │
│              └─ Score: +40                                  │
│                                                             │
│   [CRITICAL] docker_socket_mount                            │
│              └─ Score: +40 (capped contribution)            │
│                                                             │
│   [LOW] latest_tag                                          │
│              └─ Score: +5                                   │
│                                                             │
│   [MEDIUM] no_user                                          │
│              └─ Score: +15                                  │
│                                                             │
│   TOTAL SCORE: 100 (capped)                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Make Decision                                       │
│                                                             │
│   Policy Mode: enforce                                      │
│   Max Allowed Score: 50                                     │
│   Actual Score: 100                                         │
│                                                             │
│   DECISION: ✗ BLOCKED                                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Output                                              │
│                                                             │
│   ✗ Command BLOCKED                                         │
│   Risk Score: 100/100                                       │
│                                                             │
│   Risks Detected:                                           │
│     [critical] Privileged mode grants full host access      │
│     [critical] Docker socket mount allows container escape  │
│     [low] Using :latest tag is unpredictable               │
│     [medium] No user specified (defaults to root)           │
│                                                             │
│   Recommended Mitigations:                                  │
│     → Remove --privileged flag                              │
│     → Do not mount Docker socket                            │
│     → Pin image to specific tag                             │
│     → Add --user flag                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Model

Docker Sentinel operates on the principle of **defense in depth**:

```
┌─────────────────────────────────────────────────────────────┐
│                    THREAT CATEGORIES                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CONTAINER ESCAPE          PRIVILEGE ESCALATION             │
│  ─────────────────         ─────────────────────            │
│  • --privileged            • Dangerous capabilities         │
│  • Docker socket mount     • Running as root                │
│  • Host PID namespace      • Disabled seccomp/apparmor     │
│  • Host network            • SYS_ADMIN capability           │
│  • Root filesystem mount                                    │
│                                                             │
│  DATA EXPOSURE             SUPPLY CHAIN                     │
│  ─────────────             ────────────                     │
│  • Sensitive mounts        • Untrusted registries           │
│  • /etc, /home, /root      • Untagged images (:latest)      │
│  • Secrets in env vars     • No digest verification         │
│                                                             │
│  RESOURCE ABUSE            MISCONFIGURATION                 │
│  ──────────────            ────────────────                 │
│  • No memory limits        • Missing health checks          │
│  • No CPU limits           • Writable root filesystem       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

Docker Sentinel provides **pre-runtime security** by:

1. **Intercepting** Docker commands before execution
2. **Parsing** commands into structured data
3. **Evaluating** against configurable security policies
4. **Blocking** or **warning** about dangerous operations
5. **Logging** all actions for audit compliance

This prevents container escapes, privilege escalation, and data exposure **before** a container even starts.
