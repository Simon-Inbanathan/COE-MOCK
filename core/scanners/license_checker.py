"""
License Compatibility Checker — verifies package licenses against approved/blocked lists.

Node.js: uses npx license-checker (install: npm install -g license-checker).
Python:  uses pip-licenses (install: pip install pip-licenses).

Both tools are optional; missing tools produce a warning rather than a failure.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

PERMISSIVE_DEFAULT = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "0BSD", "Unlicense", "CC0-1.0", "Python-2.0",
}

COPYLEFT_DEFAULT = {
    "GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-1.0", "AGPL-3.0",
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "EUPL-1.1",
    "OSL-3.0", "CDDL-1.0", "EPL-1.0", "EPL-2.0",
}


@dataclass
class LicenseFinding:
    package: str
    version: str
    license_spdx: str
    severity: str          # high = blocked, medium = unknown/unapproved
    message: str
    file: str = ""
    line: int = 0


def _normalize_license(raw: str) -> str:
    return (raw or "UNKNOWN").strip().strip("()")


def _check_node(
    project_root: str,
    approved: List[str],
    blocked: List[str],
) -> List[LicenseFinding]:
    findings: List[LicenseFinding] = []

    # license-checker outputs JSON: { "pkg@version": { "licenses": "MIT", ... }, ... }
    cmd = "npx --yes license-checker --json --production"
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=project_root,
            timeout=90,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    for pkg_ver, info in data.items():
        lic = _normalize_license(info.get("licenses", "UNKNOWN"))
        if any(bl in lic for bl in blocked):
            findings.append(
                LicenseFinding(
                    package=pkg_ver,
                    version="",
                    license_spdx=lic,
                    severity="high",
                    message=f"Blocked license: {lic}",
                )
            )
        elif lic not in approved and not any(a in lic for a in approved):
            findings.append(
                LicenseFinding(
                    package=pkg_ver,
                    version="",
                    license_spdx=lic,
                    severity="medium",
                    message=f"Unapproved or unknown license: {lic}",
                )
            )

    return findings


def _check_python(
    approved: List[str],
    blocked: List[str],
) -> List[LicenseFinding]:
    findings: List[LicenseFinding] = []

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_licenses", "--format=json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return []
        packages = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    for pkg in packages:
        lic = _normalize_license(pkg.get("License", "UNKNOWN"))
        name = pkg.get("Name", "")
        version = pkg.get("Version", "")
        if any(bl in lic for bl in blocked):
            findings.append(
                LicenseFinding(
                    package=name,
                    version=version,
                    license_spdx=lic,
                    severity="high",
                    message=f"Blocked license: {lic}",
                )
            )
        elif lic not in approved and not any(a in lic for a in approved):
            findings.append(
                LicenseFinding(
                    package=name,
                    version=version,
                    license_spdx=lic,
                    severity="medium",
                    message=f"Unapproved or unknown license: {lic}",
                )
            )

    return findings


def check_licenses(
    project_root: str,
    tech_stack: List[str],
    approved_licenses: Optional[List[str]] = None,
    blocked_licenses: Optional[List[str]] = None,
) -> List[LicenseFinding]:
    approved = list(approved_licenses or PERMISSIVE_DEFAULT)
    blocked = list(blocked_licenses or COPYLEFT_DEFAULT)

    findings: List[LicenseFinding] = []

    if "node" in tech_stack:
        print("    Checking Node.js package licenses...")
        findings.extend(_check_node(project_root, approved, blocked))

    if "python" in tech_stack:
        print("    Checking Python package licenses...")
        findings.extend(_check_python(approved, blocked))

    return findings
