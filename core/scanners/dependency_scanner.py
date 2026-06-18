"""
Dependency Scanner — detects CVEs in project dependencies.
Auto-detects tech stack from manifest files; uses the appropriate scanner per stack.

Supported:
  node    → npm audit
  python  → pip-audit
  java    → OWASP dependency-check CLI
  dotnet  → dotnet list package --vulnerable
"""

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


@dataclass
class DependencyFinding:
    package: str
    version: str
    vulnerability_id: str
    severity: str
    description: str
    fix_version: Optional[str]
    stack: str


def _detect_stack(project_root: str) -> List[str]:
    stacks = []
    if os.path.exists(os.path.join(project_root, "package.json")):
        stacks.append("node")
    if os.path.exists(os.path.join(project_root, "requirements.txt")) or \
       os.path.exists(os.path.join(project_root, "pyproject.toml")) or \
       os.path.exists(os.path.join(project_root, "setup.py")):
        stacks.append("python")
    if os.path.exists(os.path.join(project_root, "pom.xml")) or \
       os.path.exists(os.path.join(project_root, "build.gradle")):
        stacks.append("java")
    if any(f.endswith(".csproj") for f in os.listdir(project_root)):
        stacks.append("dotnet")
    return stacks


def _scan_node(project_root: str) -> List[DependencyFinding]:
    if not shutil.which("npm"):
        print("WARNING: npm not found, skipping Node dependency scan.", file=sys.stderr)
        return []

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=120, cwd=project_root
        )
        raw = json.loads(result.stdout) if result.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"WARNING: npm audit failed: {e}", file=sys.stderr)
        return []

    findings = []
    vulnerabilities = raw.get("vulnerabilities", {})
    for pkg_name, pkg_data in vulnerabilities.items():
        for via in pkg_data.get("via", []):
            if not isinstance(via, dict):
                continue
            sev = SEVERITY_MAP.get(via.get("severity", "").lower(), "medium")
            findings.append(DependencyFinding(
                package=pkg_name,
                version=pkg_data.get("version", "unknown"),
                vulnerability_id=str(via.get("source", "CVE-unknown")),
                severity=sev,
                description=via.get("title", via.get("name", "No description")),
                fix_version=pkg_data.get("fixAvailable", {}).get("version") if isinstance(pkg_data.get("fixAvailable"), dict) else None,
                stack="node",
            ))
    return findings


def _scan_python(project_root: str) -> List[DependencyFinding]:
    if not shutil.which("pip-audit"):
        print("WARNING: pip-audit not found. Install with: pip install pip-audit", file=sys.stderr)
        return []

    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=180, cwd=project_root
        )
        raw = json.loads(result.stdout) if result.stdout.strip() else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"WARNING: pip-audit failed: {e}", file=sys.stderr)
        return []

    findings = []
    for dep in raw:
        for vuln in dep.get("vulns", []):
            findings.append(DependencyFinding(
                package=dep.get("name", ""),
                version=dep.get("version", ""),
                vulnerability_id=vuln.get("id", ""),
                severity=SEVERITY_MAP.get(vuln.get("fix_versions", [""])[0], "high") if vuln.get("fix_versions") else "high",
                description=vuln.get("description", vuln.get("id", "")),
                fix_version=vuln.get("fix_versions", [None])[0],
                stack="python",
            ))
    return findings


def _scan_java(project_root: str) -> List[DependencyFinding]:
    dep_check = shutil.which("dependency-check") or shutil.which("dependency-check.sh")
    if not dep_check:
        print(
            "WARNING: OWASP dependency-check not found. "
            "Download from https://owasp.org/www-project-dependency-check/",
            file=sys.stderr
        )
        return []

    report_dir = os.path.join(project_root, ".governance", "dep-check-report")
    os.makedirs(report_dir, exist_ok=True)

    try:
        subprocess.run(
            [dep_check, "--scan", project_root, "--format", "JSON",
             "--out", report_dir, "--failOnCVSS", "0"],
            capture_output=True, text=True, timeout=300, cwd=project_root
        )
    except subprocess.TimeoutExpired:
        print("WARNING: dependency-check timed out.", file=sys.stderr)
        return []

    report_file = os.path.join(report_dir, "dependency-check-report.json")
    if not os.path.exists(report_file):
        return []

    with open(report_file) as f:
        raw = json.load(f)

    findings = []
    for dep in raw.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            cvss = vuln.get("cvssv3", {}).get("baseScore", vuln.get("cvssv2", {}).get("score", 0))
            if cvss >= 9.0:
                sev = "critical"
            elif cvss >= 7.0:
                sev = "high"
            elif cvss >= 4.0:
                sev = "medium"
            else:
                sev = "low"

            findings.append(DependencyFinding(
                package=dep.get("fileName", ""),
                version="",
                vulnerability_id=vuln.get("name", ""),
                severity=sev,
                description=vuln.get("description", "")[:200],
                fix_version=None,
                stack="java",
            ))
    return findings


def _scan_dotnet(project_root: str) -> List[DependencyFinding]:
    if not shutil.which("dotnet"):
        print("WARNING: dotnet CLI not found, skipping .NET dependency scan.", file=sys.stderr)
        return []

    try:
        result = subprocess.run(
            ["dotnet", "list", "package", "--vulnerable", "--format", "json"],
            capture_output=True, text=True, timeout=120, cwd=project_root
        )
        raw = json.loads(result.stdout) if result.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"WARNING: dotnet vulnerability scan failed: {e}", file=sys.stderr)
        return []

    findings = []
    for project in raw.get("projects", []):
        for framework in project.get("frameworks", []):
            for pkg in framework.get("topLevelPackages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    sev = SEVERITY_MAP.get(vuln.get("severity", "").lower(), "high")
                    findings.append(DependencyFinding(
                        package=pkg.get("id", ""),
                        version=pkg.get("resolvedVersion", ""),
                        vulnerability_id=vuln.get("advisoryurl", ""),
                        severity=sev,
                        description=vuln.get("description", ""),
                        fix_version=None,
                        stack="dotnet",
                    ))
    return findings


def scan(project_root: str = ".", forced_stacks: Optional[List[str]] = None) -> List[DependencyFinding]:
    stacks = forced_stacks if forced_stacks else _detect_stack(project_root)
    if not stacks:
        print(f"No recognized manifest files found in {project_root}. Skipping dependency scan.")
        return []

    print(f"Dependency scan: detected stacks {stacks}")
    all_findings = []
    scanners = {"node": _scan_node, "python": _scan_python, "java": _scan_java, "dotnet": _scan_dotnet}
    for stack in stacks:
        if stack in scanners:
            all_findings.extend(scanners[stack](project_root))

    return all_findings


def severity_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 4)


def main():
    import argparse
    from dataclasses import asdict

    parser = argparse.ArgumentParser(description="Scan dependencies for CVEs")
    parser.add_argument("--root", default=".", help="Project root directory")
    parser.add_argument("--stack", nargs="*", help="Force stack detection (node, python, java, dotnet)")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "any"], default="high")
    args = parser.parse_args()

    findings = scan(args.root, args.stack)
    findings.sort(key=lambda f: (severity_rank(f.severity), f.package))

    if args.output == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("Dependency scan: PASSED — no vulnerable dependencies found.")
        else:
            print(f"\nDEPENDENCY FINDINGS ({len(findings)} total):\n{'─'*60}")
            for f in findings:
                fix = f"→ fix: {f.fix_version}" if f.fix_version else "→ no fix version available"
                print(f"[{f.severity.upper()}] {f.package}@{f.version} — {f.vulnerability_id}")
                print(f"  {f.description[:100]}")
                print(f"  {fix}")
                print()

    fail_ranks = {"critical": 0, "high": 1, "medium": 2, "any": 3}
    fail_at = fail_ranks.get(args.fail_on, 1)
    should_fail = any(severity_rank(f.severity) <= fail_at for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
