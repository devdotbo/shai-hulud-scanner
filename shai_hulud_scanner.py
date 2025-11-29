#!/usr/bin/env python3
"""
Shai Hulud 2.0 Scanner

Scans git repositories for indicators of compromise (IoCs) related to the
Shai Hulud 2.0 npm supply chain worm.

References:
- https://www.tenable.com/blog/faq-about-sha1-hulud-2-0-the-second-coming-of-the-npm-supply-chain-campaign
- https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import requests
import yaml

if TYPE_CHECKING:
    from collections.abc import Iterator


# IoC Sources
IOC_SOURCES = {
    "tenable": "https://raw.githubusercontent.com/tenable/shai-hulud-second-coming-affected-packages/main/list.json",
}

# Known malicious file patterns
PAYLOAD_FILES = {
    "setup_bun.js",
    "bun_environment.js",
}

EXFIL_FILES = {
    "cloud.json",
    "contents.json",
    "truffleSecrets.json",
}

SUSPICIOUS_WORKFLOWS = {
    ".github/workflows/discussion.yaml",
    ".github/workflows/discussion.yml",
}

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules",
    ".pnpm-store",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
}

# Lockfile names
LOCKFILES = {
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
}

# Cache settings
CACHE_DIR = Path.home() / ".cache" / "shai-hulud-scanner"
CACHE_TTL = 86400  # 24 hours in seconds


class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        """Disable colors for non-TTY output."""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.BOLD = ""
        cls.RESET = ""


@dataclass
class Finding:
    """Represents a single IoC finding."""

    repo_path: str
    finding_type: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    file_path: str | None = None
    package_name: str | None = None
    package_version: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "repo_path": self.repo_path,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "package_name": self.package_name,
            "package_version": self.package_version,
        }


@dataclass
class ScanResult:
    """Results from scanning a single repository."""

    repo_path: str
    findings: list[Finding] = field(default_factory=list)
    scanned_at: float = field(default_factory=time.time)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.findings, key=lambda f: severity_order.get(f.severity, 99)).severity

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "repo_path": self.repo_path,
            "is_clean": self.is_clean,
            "max_severity": self.max_severity,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_at": self.scanned_at,
        }


class IoCCache:
    """Manages caching of IoC lists."""

    def __init__(self, cache_dir: Path = CACHE_DIR, ttl: int = CACHE_TTL) -> None:
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, url: str) -> Path:
        """Get cache file path for a URL."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        return self.cache_dir / f"{url_hash}.json"

    def get(self, url: str) -> dict | list | None:
        """Get cached data if valid."""
        cache_path = self._cache_path(url)
        if not cache_path.exists():
            return None

        try:
            with cache_path.open() as f:
                cached = json.load(f)

            if time.time() - cached.get("cached_at", 0) > self.ttl:
                return None

            return cached.get("data")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, url: str, data: dict | list) -> None:
        """Cache data for a URL."""
        cache_path = self._cache_path(url)
        try:
            with cache_path.open("w") as f:
                json.dump({"cached_at": time.time(), "data": data}, f)
        except OSError:
            pass  # Silently fail cache writes

    def clear(self) -> None:
        """Clear all cached data."""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except OSError:
                pass


class ShaiHuludScanner:
    """Main scanner class for detecting Shai Hulud 2.0 IoCs."""

    def __init__(
        self,
        verbose: bool = False,
        refresh_ioc: bool = False,
        json_output: bool = False,
    ) -> None:
        self.verbose = verbose
        self.json_output = json_output
        self.cache = IoCCache()

        if refresh_ioc:
            self.cache.clear()

        if json_output and not sys.stdout.isatty():
            Colors.disable()

        self.compromised_packages: dict[str, set[str]] = {}
        self._load_ioc_lists()

    def _log(self, message: str, level: str = "info") -> None:
        """Log message if not in JSON mode."""
        if self.json_output:
            return

        prefix = ""
        if level == "error":
            prefix = f"{Colors.RED}[ERROR]{Colors.RESET} "
        elif level == "warning":
            prefix = f"{Colors.YELLOW}[WARN]{Colors.RESET} "
        elif level == "success":
            prefix = f"{Colors.GREEN}[OK]{Colors.RESET} "
        elif level == "info" and self.verbose:
            prefix = f"{Colors.BLUE}[INFO]{Colors.RESET} "
        elif level == "info":
            return  # Skip info messages in non-verbose mode

        print(f"{prefix}{message}")

    def _fetch_json(self, url: str) -> dict | list | None:
        """Fetch JSON from URL with caching."""
        cached = self.cache.get(url)
        if cached is not None:
            self._log(f"Using cached IoC data for {url}")
            return cached

        try:
            self._log(f"Fetching IoC data from {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            self.cache.set(url, data)
            return data
        except requests.RequestException as e:
            self._log(f"Failed to fetch {url}: {e}", "warning")
            return None

    def _load_ioc_lists(self) -> None:
        """Load compromised package lists from IoC sources."""
        # Tenable list
        tenable_data = self._fetch_json(IOC_SOURCES["tenable"])
        if tenable_data and isinstance(tenable_data, list):
            for entry in tenable_data:
                name = entry.get("name")
                version = entry.get("version")
                if name and version:
                    if name not in self.compromised_packages:
                        self.compromised_packages[name] = set()
                    self.compromised_packages[name].add(version)

        self._log(
            f"Loaded {len(self.compromised_packages)} compromised packages",
            "info" if self.compromised_packages else "warning",
        )

    def find_repos(self, root: Path) -> Iterator[Path]:
        """Find all git repositories under root path."""
        root = root.resolve()

        if (root / ".git").is_dir():
            yield root

        for dirpath, dirnames, _ in os.walk(root):
            # Modify dirnames in-place to skip certain directories
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for dirname in dirnames:
                full_path = Path(dirpath) / dirname
                if (full_path / ".git").is_dir():
                    yield full_path

    def _scan_for_files(
        self,
        repo_path: Path,
        filenames: set[str],
        finding_type: str,
        severity: str,
        description_template: str,
    ) -> list[Finding]:
        """Scan repository for specific filenames."""
        findings = []

        for dirpath, dirnames, files in os.walk(repo_path):
            # Skip certain directories
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for filename in files:
                if filename in filenames:
                    file_path = Path(dirpath) / filename
                    rel_path = file_path.relative_to(repo_path)
                    findings.append(
                        Finding(
                            repo_path=str(repo_path),
                            finding_type=finding_type,
                            severity=severity,
                            description=description_template.format(filename=filename),
                            file_path=str(rel_path),
                        )
                    )

        return findings

    def _scan_for_workflow(self, repo_path: Path) -> list[Finding]:
        """Scan for suspicious GitHub workflow files."""
        findings = []

        for workflow_path in SUSPICIOUS_WORKFLOWS:
            full_path = repo_path / workflow_path
            if full_path.exists():
                findings.append(
                    Finding(
                        repo_path=str(repo_path),
                        finding_type="malicious_workflow",
                        severity="critical",
                        description=f"Suspicious workflow file found: {workflow_path}",
                        file_path=workflow_path,
                    )
                )

        return findings

    def _parse_pnpm_lock(self, lockfile_path: Path) -> dict[str, str]:
        """Parse pnpm-lock.yaml and return package:version mapping."""
        packages = {}
        try:
            with lockfile_path.open() as f:
                lock_data = yaml.safe_load(f)

            if not lock_data:
                return packages

            # pnpm lockfile v6+ format
            if "packages" in lock_data:
                for pkg_key in lock_data["packages"]:
                    # Format: /@scope/name@version or /name@version
                    match = re.match(r"^/?(@?[^@]+)@(.+)$", pkg_key)
                    if match:
                        name, version = match.groups()
                        # Clean up the name (remove leading /)
                        name = name.lstrip("/")
                        packages[name] = version

            # pnpm lockfile v5 format (dependencies at root)
            if "dependencies" in lock_data:
                for name, info in lock_data.get("dependencies", {}).items():
                    if isinstance(info, dict) and "version" in info:
                        packages[name] = info["version"]
                    elif isinstance(info, str):
                        packages[name] = info

        except (yaml.YAMLError, OSError) as e:
            self._log(f"Failed to parse {lockfile_path}: {e}", "warning")

        return packages

    def _parse_package_lock(self, lockfile_path: Path) -> dict[str, str]:
        """Parse package-lock.json and return package:version mapping."""
        packages = {}
        try:
            with lockfile_path.open() as f:
                lock_data = json.load(f)

            # npm lockfile v2/v3 format
            if "packages" in lock_data:
                for pkg_path, info in lock_data["packages"].items():
                    if not pkg_path:  # Skip root package
                        continue
                    # Extract package name from path
                    name = pkg_path.split("node_modules/")[-1]
                    version = info.get("version", "")
                    if name and version:
                        packages[name] = version

            # npm lockfile v1 format
            elif "dependencies" in lock_data:

                def extract_deps(deps: dict, prefix: str = "") -> None:
                    for name, info in deps.items():
                        if isinstance(info, dict):
                            version = info.get("version", "")
                            if version:
                                packages[name] = version
                            # Recurse into nested dependencies
                            if "dependencies" in info:
                                extract_deps(info["dependencies"])

                extract_deps(lock_data["dependencies"])

        except (json.JSONDecodeError, OSError) as e:
            self._log(f"Failed to parse {lockfile_path}: {e}", "warning")

        return packages

    def _parse_yarn_lock(self, lockfile_path: Path) -> dict[str, str]:
        """Parse yarn.lock and return package:version mapping."""
        packages = {}
        try:
            content = lockfile_path.read_text()

            # Simple regex-based parsing for yarn.lock
            # Format: "package@version": or package@version:
            current_package = None
            for line in content.splitlines():
                # Match package header: "name@version", name@version:
                header_match = re.match(r'^"?([^@\s]+)@[^"]+', line)
                if header_match and not line.startswith(" "):
                    current_package = header_match.group(1)

                # Match version line
                version_match = re.match(r'^\s+version\s+"?([^"]+)"?', line)
                if version_match and current_package:
                    packages[current_package] = version_match.group(1)
                    current_package = None

        except OSError as e:
            self._log(f"Failed to parse {lockfile_path}: {e}", "warning")

        return packages

    def _scan_lockfiles(self, repo_path: Path) -> list[Finding]:
        """Scan lockfiles for compromised packages."""
        findings = []

        for lockfile_name in LOCKFILES:
            lockfile_path = repo_path / lockfile_name
            if not lockfile_path.exists():
                continue

            packages: dict[str, str] = {}
            if lockfile_name == "pnpm-lock.yaml":
                packages = self._parse_pnpm_lock(lockfile_path)
            elif lockfile_name == "package-lock.json":
                packages = self._parse_package_lock(lockfile_path)
            elif lockfile_name == "yarn.lock":
                packages = self._parse_yarn_lock(lockfile_path)

            for pkg_name, pkg_version in packages.items():
                if pkg_name in self.compromised_packages:
                    compromised_versions = self.compromised_packages[pkg_name]
                    if pkg_version in compromised_versions:
                        findings.append(
                            Finding(
                                repo_path=str(repo_path),
                                finding_type="compromised_package",
                                severity="critical",
                                description=f"Compromised package version in {lockfile_name}",
                                file_path=lockfile_name,
                                package_name=pkg_name,
                                package_version=pkg_version,
                            )
                        )

        return findings

    def _scan_package_json(self, repo_path: Path) -> list[Finding]:
        """Scan package.json for suspicious preinstall scripts."""
        findings = []
        package_json_path = repo_path / "package.json"

        if not package_json_path.exists():
            return findings

        try:
            with package_json_path.open() as f:
                pkg_data = json.load(f)

            scripts = pkg_data.get("scripts", {})
            preinstall = scripts.get("preinstall", "")

            # Check for suspicious preinstall patterns
            suspicious_patterns = [
                r"setup_bun\.js",
                r"bun_environment\.js",
                r"node\s+.*bun",
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, preinstall, re.IGNORECASE):
                    findings.append(
                        Finding(
                            repo_path=str(repo_path),
                            finding_type="suspicious_preinstall",
                            severity="critical",
                            description=f"Suspicious preinstall script: {preinstall[:80]}",
                            file_path="package.json",
                        )
                    )
                    break

        except (json.JSONDecodeError, OSError) as e:
            self._log(f"Failed to parse {package_json_path}: {e}", "warning")

        return findings

    def scan_repo(self, repo_path: Path) -> ScanResult:
        """Scan a single repository for IoCs."""
        result = ScanResult(repo_path=str(repo_path))

        # Scan for payload files
        result.findings.extend(
            self._scan_for_files(
                repo_path,
                PAYLOAD_FILES,
                "payload_file",
                "critical",
                "Malicious payload file found: {filename}",
            )
        )

        # Scan for exfiltration artifacts
        result.findings.extend(
            self._scan_for_files(
                repo_path,
                EXFIL_FILES,
                "exfil_artifact",
                "high",
                "Potential exfiltration artifact found: {filename}",
            )
        )

        # Scan for malicious workflows
        result.findings.extend(self._scan_for_workflow(repo_path))

        # Scan lockfiles for compromised packages
        result.findings.extend(self._scan_lockfiles(repo_path))

        # Scan package.json for suspicious scripts
        result.findings.extend(self._scan_package_json(repo_path))

        return result

    def scan(self, root_path: Path) -> list[ScanResult]:
        """Scan all repositories under root path."""
        results = []
        repos = list(self.find_repos(root_path))

        if not self.json_output:
            print(f"\n{Colors.BOLD}Shai Hulud 2.0 Scanner{Colors.RESET}")
            print(f"Scanning: {root_path}")
            print(f"Found {len(repos)} git repositories\n")

        for repo in repos:
            if not self.json_output:
                print(f"Scanning: {repo.name} ... ", end="", flush=True)

            result = self.scan_repo(repo)
            results.append(result)

            if not self.json_output:
                if result.is_clean:
                    print(f"{Colors.GREEN}clean{Colors.RESET}")
                else:
                    severity_color = {
                        "critical": Colors.RED,
                        "high": Colors.MAGENTA,
                        "medium": Colors.YELLOW,
                        "low": Colors.BLUE,
                    }.get(result.max_severity, Colors.YELLOW)
                    print(f"{severity_color}{len(result.findings)} finding(s){Colors.RESET}")

        return results

    def print_summary(self, results: list[ScanResult]) -> None:
        """Print scan summary."""
        if self.json_output:
            output = {
                "scan_results": [r.to_dict() for r in results],
                "summary": {
                    "total_repos": len(results),
                    "clean_repos": sum(1 for r in results if r.is_clean),
                    "infected_repos": sum(1 for r in results if not r.is_clean),
                    "total_findings": sum(len(r.findings) for r in results),
                },
            }
            print(json.dumps(output, indent=2))
            return

        clean_count = sum(1 for r in results if r.is_clean)
        infected_count = len(results) - clean_count
        total_findings = sum(len(r.findings) for r in results)

        print(f"\n{Colors.BOLD}Scan Summary{Colors.RESET}")
        print("-" * 40)
        print(f"Total repositories scanned: {len(results)}")
        print(f"{Colors.GREEN}Clean: {clean_count}{Colors.RESET}")

        if infected_count > 0:
            print(f"{Colors.RED}Potentially infected: {infected_count}{Colors.RESET}")
            print(f"Total findings: {total_findings}")

            print(f"\n{Colors.BOLD}Findings by Repository:{Colors.RESET}")
            for result in results:
                if not result.is_clean:
                    print(f"\n{Colors.YELLOW}{result.repo_path}{Colors.RESET}")
                    for finding in result.findings:
                        severity_color = {
                            "critical": Colors.RED,
                            "high": Colors.MAGENTA,
                            "medium": Colors.YELLOW,
                            "low": Colors.BLUE,
                        }.get(finding.severity, Colors.RESET)
                        print(
                            f"  {severity_color}[{finding.severity.upper()}]{Colors.RESET} "
                            f"{finding.finding_type}: {finding.description}"
                        )
                        if finding.file_path:
                            print(f"    File: {finding.file_path}")
                        if finding.package_name:
                            print(f"    Package: {finding.package_name}@{finding.package_version}")

            print(f"\n{Colors.BOLD}Recommended Actions:{Colors.RESET}")
            print("1. Rotate all credentials (GitHub, npm, cloud, SSH keys)")
            print("2. Check your GitHub account for repos with 'Sha1-Hulud' description")
            print("3. Clear node_modules and reinstall from known-good lockfile")
            print("4. Review any npm packages you maintain for unauthorized publishes")
        else:
            print(f"\n{Colors.GREEN}All repositories appear clean.{Colors.RESET}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scan git repositories for Shai Hulud 2.0 npm worm IoCs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ~/Projects              Scan all repos under ~/Projects
  %(prog)s . --json                Output results as JSON
  %(prog)s ~/Projects --refresh    Force refresh IoC cache
  %(prog)s ~/Projects -v           Verbose output
        """,
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Root directory to scan for git repositories",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--refresh-ioc",
        "--refresh",
        action="store_true",
        help="Force refresh IoC cache",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    if not args.path.exists():
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        return 1

    if not args.path.is_dir():
        print(f"Error: Path is not a directory: {args.path}", file=sys.stderr)
        return 1

    scanner = ShaiHuludScanner(
        verbose=args.verbose,
        refresh_ioc=args.refresh_ioc,
        json_output=args.json,
    )

    results = scanner.scan(args.path)
    scanner.print_summary(results)

    # Return non-zero exit code if any findings
    has_findings = any(not r.is_clean for r in results)
    return 1 if has_findings else 0


if __name__ == "__main__":
    sys.exit(main())
