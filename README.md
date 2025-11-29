# Shai Hulud Scanner

![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue)
![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-green)

A Python CLI tool that scans git repositories for indicators of compromise (IoCs) related to the **Shai Hulud 2.0** npm supply chain worm.

## Background

Shai Hulud 2.0 is an npm supply chain worm that compromises legitimate npm packages through hijacked maintainer accounts. Once installed, the malware steals credentials (npm tokens, GitHub PATs, cloud keys, SSH keys), exfiltrates sensitive data to attacker-controlled repositories, and self-propagates by backdooring any npm packages the victim maintains. This scanner helps detect if your repositories have been affected.

For a detailed security playbook including hardening recommendations and remediation steps, see [anti-worm.md](anti-worm.md).

## Features

The scanner detects the following IoCs:

- **Payload files** - `setup_bun.js` and `bun_environment.js` (critical severity)
- **Exfiltration artifacts** - `cloud.json`, `contents.json`, `truffleSecrets.json` (high severity)
- **Malicious workflows** - `.github/workflows/discussion.yaml` (critical severity)
- **Compromised packages** - Known bad package versions in lockfiles (critical severity)
- **Suspicious preinstall scripts** - References to malicious files in `package.json` (critical severity)

## Installation

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/yourusername/shai-hulud-scanner.git
cd shai-hulud-scanner
uv sync
```

## Usage

```bash
# Scan all repositories under a directory
uv run shai-hulud-scanner ~/Projects

# Output results as JSON
uv run shai-hulud-scanner ~/Projects --json

# Force refresh the IoC cache
uv run shai-hulud-scanner ~/Projects --refresh

# Enable verbose output
uv run shai-hulud-scanner ~/Projects -v
```

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `path` | Root directory to scan for git repositories (required) |
| `--json` | Output results in JSON format |
| `--refresh`, `--refresh-ioc` | Force refresh of cached IoC lists |
| `-v`, `--verbose` | Enable verbose output with detailed info messages |

## Output Formats

### Human-Readable (Default)

Color-coded terminal output with severity indicators:
- Red: Critical findings
- Magenta: High severity findings
- Green: Clean repositories

Includes a summary with total repos scanned, clean/infected counts, and recommended actions if findings are detected.

### JSON Format

```json
{
  "scan_results": [
    {
      "repo_path": "/path/to/repo",
      "is_clean": false,
      "max_severity": "critical",
      "findings": [
        {
          "repo_path": "/path/to/repo",
          "finding_type": "compromised_package",
          "severity": "critical",
          "description": "Compromised package version in pnpm-lock.yaml",
          "file_path": "pnpm-lock.yaml",
          "package_name": "example-package",
          "package_version": "1.2.3"
        }
      ],
      "scanned_at": 1732000000.123
    }
  ],
  "summary": {
    "total_repos": 10,
    "clean_repos": 8,
    "infected_repos": 2,
    "total_findings": 5
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All repositories clean, no findings detected |
| `1` | Findings detected or error occurred |

## Supported Lockfile Formats

The scanner parses the following lockfile formats to detect compromised package versions:

- **pnpm-lock.yaml** - Supports both v5 and v6+ formats
- **package-lock.json** - Supports npm v1, v2, and v3 formats
- **yarn.lock** - Regex-based parsing

## IoC Sources

Compromised package lists are fetched from [Tenable's affected packages repository](https://github.com/tenable/shai-hulud-second-coming-affected-packages).

## Caching

IoC lists are cached locally to avoid repeated network requests:

- **Cache location**: `~/.cache/shai-hulud-scanner/`
- **Cache TTL**: 24 hours
- **Force refresh**: Use `--refresh` or `--refresh-ioc` flag

## Development

```bash
# Install with dev dependencies
uv sync --dev

# Run linter
uv run ruff check .

# Format code
uv run ruff format .
```

## Related Resources

- [Tenable FAQ on Sha1-Hulud 2.0](https://www.tenable.com/blog/faq-about-sha1-hulud-2-0-the-second-coming-of-the-npm-supply-chain-campaign)
- [Datadog Security Labs Analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Wiz Blog Post](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Security Playbook](anti-worm.md) - Detailed hardening and remediation guide
