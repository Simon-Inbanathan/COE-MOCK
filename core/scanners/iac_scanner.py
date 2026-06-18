"""
IaC Security Scanner — wraps Checkov (primary) with tfsec fallback.

Detects security misconfigurations in:
  Terraform (.tf), CloudFormation (.json/.yaml), Kubernetes manifests,
  Dockerfiles, GitHub Actions workflows, Helm charts.

Install: pip install checkov
         OR: brew install tfsec / choco install tfsec

Returns IacFinding dataclasses that roll up into the security scorecard.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Tuple

IAC_FILE_PATTERNS = {
    ".tf": "terraform",
    ".hcl": "terraform",
    "Dockerfile": "dockerfile",
    "dockerfile": "dockerfile",
}

IAC_YAML_KEYWORDS = (
    "AWSTemplateFormatVersion",
    "apiVersion",        # Kubernetes
    "kind: Deployment",
    "kind: Service",
    "kind: Pod",
    "kind: Ingress",
    "Resources:",        # CloudFormation
)

ALWAYS_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


@dataclass
class IacFinding:
    file: str
    line: int
    check_id: str
    resource: str
    message: str
    severity: str          # critical | high | medium | low
    framework: str         # terraform | cloudformation | kubernetes | dockerfile
    guideline: str = ""


def _detect_iac_files(paths: List[str]) -> bool:
    """Return True if any IaC files exist under the given paths."""
    for path in paths:
        if os.path.isfile(path):
            fname = os.path.basename(path)
            _, ext = os.path.splitext(fname)
            if ext in IAC_FILE_PATTERNS or fname in IAC_FILE_PATTERNS:
                return True
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ALWAYS_SKIP]
                for fname in files:
                    _, ext = os.path.splitext(fname)
                    if ext in IAC_FILE_PATTERNS or fname in IAC_FILE_PATTERNS:
                        return True
                    if ext in (".yml", ".yaml"):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                sample = f.read(512)
                            if any(kw in sample for kw in IAC_YAML_KEYWORDS):
                                return True
                        except OSError:
                            pass
    return False


def _severity_from_checkov(severity_str: str) -> str:
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "low",
    }
    return mapping.get((severity_str or "").upper(), "medium")


def run_checkov(paths: List[str]) -> Tuple[List[IacFinding], bool]:
    """
    Run Checkov on the given paths and return (findings, tool_available).
    Returns ([], False) if Checkov is not installed.
    """
    import shutil
    if not shutil.which("checkov"):
        # Try as a Python module
        try:
            subprocess.run(
                [sys.executable, "-m", "checkov.main", "--version"],
                capture_output=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return [], False

    scan_dirs = [p for p in paths if os.path.isdir(p)]
    scan_files = [p for p in paths if os.path.isfile(p)]
    targets = scan_dirs if scan_dirs else scan_files[:1] if scan_files else ["."]

    cmd = [
        sys.executable, "-m", "checkov.main",
        "--directory", targets[0],
        "--output", "json",
        "--quiet",
        "--compact",
        "--framework", "terraform,cloudformation,kubernetes,dockerfile,github_actions",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return [], False

    raw_output = result.stdout.strip()
    if not raw_output:
        return [], True

    findings: List[IacFinding] = []

    try:
        # Checkov may output multiple JSON objects (one per framework) — try wrapping
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        try:
            # Sometimes multiple JSON objects are concatenated
            parts = raw_output.split("\n}\n{")
            data = json.loads(parts[0] + "\n}")
        except json.JSONDecodeError:
            return [], True

    def _extract(obj):
        if isinstance(obj, dict):
            for failed in obj.get("results", {}).get("failed_checks", []):
                check = failed.get("check", {})
                severity_raw = check.get("severity", failed.get("severity", "MEDIUM"))
                severity = _severity_from_checkov(severity_raw or "MEDIUM")
                file_path = failed.get("repo_file_path", failed.get("file_path", ""))
                line_range = failed.get("file_line_range", [0, 0])
                line = line_range[0] if line_range else 0
                findings.append(
                    IacFinding(
                        file=file_path,
                        line=line,
                        check_id=check.get("id", ""),
                        resource=failed.get("resource", ""),
                        message=check.get("name", ""),
                        severity=severity,
                        framework=failed.get("check_type", "terraform"),
                        guideline=check.get("guideline", ""),
                    )
                )
        elif isinstance(obj, list):
            for item in obj:
                _extract(item)

    _extract(data)
    return findings, True


def run_tfsec(paths: List[str]) -> Tuple[List[IacFinding], bool]:
    """
    Run tfsec on the given paths and return (findings, tool_available).
    tfsec is Terraform-only; used as fallback when Checkov is unavailable.
    """
    import shutil
    if not shutil.which("tfsec"):
        return [], False

    scan_dir = next((p for p in paths if os.path.isdir(p)), ".")
    cmd = ["tfsec", scan_dir, "--format", "json", "--no-colour"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        raw = result.stdout.strip()
        if not raw:
            return [], True
        data = json.loads(raw)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return [], False

    findings: List[IacFinding] = []
    for res in data.get("results", []):
        sev = res.get("severity", "MEDIUM")
        findings.append(
            IacFinding(
                file=res.get("location", {}).get("filename", ""),
                line=res.get("location", {}).get("start_line", 0),
                check_id=res.get("rule_id", res.get("long_id", "")),
                resource=res.get("block", ""),
                message=res.get("description", res.get("rule_description", "")),
                severity=_severity_from_checkov(sev),
                framework="terraform",
                guideline=res.get("links", [""])[0] if res.get("links") else "",
            )
        )
    return findings, True


def scan(paths: List[str]) -> List[IacFinding]:
    """
    Scan for IaC security issues. Tries Checkov first, falls back to tfsec.
    Returns an empty list (not an error) if no IaC files exist or tools unavailable.
    """
    if not _detect_iac_files(paths):
        return []

    findings, available = run_checkov(paths)
    if not available:
        findings, available = run_tfsec(paths)
        if not available:
            print(
                "  INFO: No IaC scanner found. Install Checkov: pip install checkov",
                file=sys.stderr,
            )
    return findings
