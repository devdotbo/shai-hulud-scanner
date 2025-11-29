# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Shai Hulud Scanner is a Python CLI tool that scans git repositories for indicators of compromise (IoCs) related to the Shai Hulud 2.0 npm supply chain worm. It detects compromised npm packages, malicious payload files, exfiltration artifacts, and suspicious preinstall scripts.

## Commands

### Setup
```bash
uv sync                    # Install dependencies
uv sync --dev              # Install with dev dependencies
```

### Running the Scanner
```bash
uv run python shai_hulud_scanner.py ~/Projects        # Scan repos under a directory
uv run python shai_hulud_scanner.py . --json          # Output as JSON
uv run python shai_hulud_scanner.py ~/Projects --refresh  # Force refresh IoC cache
uv run python shai_hulud_scanner.py ~/Projects -v     # Verbose output
```

### Linting
```bash
uv run ruff check .        # Run linter
uv run ruff format .       # Format code
```

## Architecture

The scanner (`shai_hulud_scanner.py`) is a single-file module with these key components:

- **ShaiHuludScanner**: Main class that orchestrates all scanning operations
  - Fetches and caches compromised package lists from Tenable's IoC repository
  - Recursively finds git repos and scans each for IoCs
  - Parses lockfiles (pnpm-lock.yaml, package-lock.json, yarn.lock) to detect compromised package versions
  - Searches for known malicious files: `setup_bun.js`, `bun_environment.js`, exfiltration JSONs, suspicious workflows

- **IoCCache**: Handles 24-hour caching of IoC lists in `~/.cache/shai-hulud-scanner/`

- **Finding/ScanResult**: Dataclasses for structured results with severity levels (critical/high/medium/low)

The scanner checks for:
1. Payload files (`setup_bun.js`, `bun_environment.js`)
2. Exfiltration artifacts (`cloud.json`, `contents.json`, `truffleSecrets.json`)
3. Malicious workflows (`.github/workflows/discussion.yaml`)
4. Compromised packages in lockfiles (matched against Tenable's IoC list)
5. Suspicious preinstall scripts in `package.json`

Exit code is 0 if clean, 1 if any findings detected.
