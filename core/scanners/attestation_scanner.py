"""
Code Generation Attestation Gate.

Enforces rules for AI-generated code at the IDE level (on-save) and as an explicit
stage in the CI/CD pipeline. All gates produce AttestationFinding objects that roll
up into the governance scorecard.

Gates:
  1. complexity     — cyclomatic complexity ≤ threshold per function (lizard)
  2. sensitive_area — auth / crypto / PHI code flags mandatory human review
  3. license        — newly added packages must use approved licenses
  4. provenance     — AI model + optional version annotation in commit metadata

Exit codes (CLI):
  0 — all gates passed
  1 — blocking findings (severity ≥ block_on_severity)
"""

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from core.scanners.complexity_checker import ComplexityFinding, check_complexity
from core.scanners.license_checker import LicenseFinding, check_licenses


# ── Sensitive-area keyword gates ──────────────────────────────────────────────

SENSITIVE_GATES = {
    "crypto": {
        "keywords": [
            "encrypt", "decrypt", "cipher", "aes_", "rsa_", "hmac",
            "pbkdf2", "bcrypt", "argon2", "crypto.create", "cryptography",
            "keystore", "privatekey", "private_key", "x509", "pkcs",
        ],
        "severity": "high",
        "message": "Cryptographic operation detected — mandatory human review required",
        "remediation": (
            "Have a security engineer review this function before merging. "
            "Verify algorithm, key size, IV handling, and error paths."
        ),
    },
    "auth": {
        "keywords": [
            "authenticate(", "authorize(", "login(", "logout(",
            "verify_token", "validate_token", "decode_jwt", "create_jwt",
            "check_permission", "has_role", "is_authorized",
            "session.create", "oauth", "saml", "bearer ",
        ],
        "severity": "high",
        "message": "Authentication/authorization code detected — mandatory human review required",
        "remediation": (
            "Have a security engineer verify access control logic, "
            "token validation, and privilege escalation paths."
        ),
    },
    "pii_phi": {
        "keywords": [
            "ssn", "social_security", "date_of_birth", "dateofbirth",
            "medical_record", "diagnosis_code", "icd_code", "npi_",
            "subscriber_id", "beneficiary_id", "health_plan_id",
            "patient_id", "member_id", "phi_", "pii_",
        ],
        "severity": "critical",
        "message": "PHI/PII field access detected — mandatory human review required per HIPAA",
        "remediation": (
            "Assign a reviewer with HIPAA expertise. Verify: field is not logged, "
            "access is audited, data is encrypted at rest and in transit."
        ),
    },
}

_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".go",
    ".rb", ".php",
}

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".angular",
}

# Regex to detect function / method definitions across languages
_FUNC_RE = re.compile(
    r"""
    (?:                             # Python / JS async
        \bdef\s+(\w+)\s*\(
      | \bfunction\s+(\w+)\s*\(
      | \basync\s+function\s+(\w+)\s*\(
    )
    |
    (?:                             # Java / C# / TS methods
        (?:public|private|protected|static|async)\s+
        (?:[\w<>\[\]]+\s+)+         # return type(s)
        (\w+)\s*\(
    )
    """,
    re.VERBOSE,
)


@dataclass
class AttestationFinding:
    gate: str                         # complexity | sensitive_area | license | provenance
    severity: str                     # critical | high | medium | low
    file: str
    line: int
    function_name: str
    message: str
    detail: str = ""
    requires_human_review: bool = False
    remediation: str = ""


@dataclass
class AttestationReport:
    findings: List[AttestationFinding] = field(default_factory=list)
    complexity_violations: int = 0
    sensitive_areas_flagged: int = 0
    license_issues: int = 0
    provenance_valid: bool = True
    overall_passed: bool = True


# ── Sensitive area scanner ────────────────────────────────────────────────────

def _scan_sensitive_areas(paths: List[str]) -> List[AttestationFinding]:
    findings: List[AttestationFinding] = []

    all_files: List[str] = []
    for path in paths:
        if os.path.isfile(path):
            all_files.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for fname in files:
                    all_files.append(os.path.join(root, fname))

    seen: set = set()

    for fpath in all_files:
        if os.path.splitext(fpath)[1].lower() not in _CODE_EXTENSIONS:
            continue

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue

        current_func = "<module>"
        for line_no, raw_line in enumerate(lines, start=1):
            line_lower = raw_line.lower()

            fm = _FUNC_RE.search(raw_line)
            if fm:
                current_func = next((g for g in fm.groups() if g), current_func)

            stripped = raw_line.strip()
            if stripped.startswith(("#", "//")):
                continue

            for gate_name, gate in SENSITIVE_GATES.items():
                for kw in gate["keywords"]:
                    if kw in line_lower:
                        key = (fpath, line_no, gate_name)
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                AttestationFinding(
                                    gate="sensitive_area",
                                    severity=gate["severity"],
                                    file=fpath,
                                    line=line_no,
                                    function_name=current_func,
                                    message=gate["message"],
                                    detail=f"gate={gate_name}, keyword='{kw}'",
                                    requires_human_review=True,
                                    remediation=gate["remediation"],
                                )
                            )
                        break  # one finding per gate per line

    return findings


# ── Provenance checker ────────────────────────────────────────────────────────

_AI_TAG_RE = re.compile(r"\[ai:([\w,\s@.\-]+)\]", re.IGNORECASE)


def _check_provenance(
    commit_msg: str,
    require_model_version: bool,
) -> Optional[AttestationFinding]:
    if not commit_msg:
        return None

    match = _AI_TAG_RE.search(commit_msg)
    if not match:
        return None  # No AI tag → human-only commit, not a provenance violation

    if not require_model_version:
        return None

    for tool in re.split(r"[,\s]+", match.group(1)):
        tool = tool.strip()
        if not tool or tool.lower() in ("none", "reviewed"):
            continue
        if "@" not in tool:
            return AttestationFinding(
                gate="provenance",
                severity="medium",
                file="commit message",
                line=0,
                function_name="",
                message=f"AI tool '{tool}' missing model-version annotation",
                detail="attestation.provenance.require_model_version is enabled",
                requires_human_review=False,
                remediation=(
                    "Amend commit message to include model version, e.g. "
                    "[ai:claude@claude-sonnet-4-6]"
                ),
            )
    return None


# ── Main entry point ──────────────────────────────────────────────────────────

def run_attestation(
    paths: List[str],
    config,                     # GovernanceConfig (from config_validator)
    commit_msg: str = "",
    project_root: str = ".",
) -> AttestationReport:
    att = getattr(config, "attestation", None)
    if att is None or not getattr(att, "enabled", True):
        return AttestationReport(overall_passed=True)

    all_findings: List[AttestationFinding] = []

    # ── Gate 1: Complexity ───────────────────────────────────────────────
    if getattr(att, "complexity_enabled", True):
        max_ccn = getattr(att, "max_cyclomatic", 10)
        print(f"  [ATTEST] Complexity check (max CCN={max_ccn})...")
        for cf in check_complexity(paths, max_ccn):
            all_findings.append(
                AttestationFinding(
                    gate="complexity",
                    severity=cf.severity,
                    file=cf.file,
                    line=cf.line,
                    function_name=cf.function_name,
                    message=cf.message,
                    detail=f"CCN={cf.cyclomatic_complexity}, threshold={cf.threshold}",
                    requires_human_review=(cf.severity == "critical"),
                    remediation=(
                        "Refactor: extract helper functions or simplify branching "
                        "until CCN ≤ threshold."
                    ),
                )
            )

    # ── Gate 2: Sensitive areas ──────────────────────────────────────────
    if getattr(att, "sensitive_areas_enabled", True):
        print("  [ATTEST] Sensitive area scan (auth / crypto / PHI)...")
        all_findings.extend(_scan_sensitive_areas(paths))

    # ── Gate 3: License compatibility ────────────────────────────────────
    if getattr(att, "license_check_enabled", False):
        print("  [ATTEST] License compatibility check...")
        approved = getattr(att, "approved_licenses", [])
        blocked = getattr(att, "blocked_licenses", [])
        for lf in check_licenses(project_root, config.team.tech_stack, approved, blocked):
            all_findings.append(
                AttestationFinding(
                    gate="license",
                    severity=lf.severity,
                    file=lf.file or "package manifest",
                    line=lf.line,
                    function_name="",
                    message=lf.message,
                    detail=f"license={lf.license_spdx}, package={lf.package}",
                    requires_human_review=(lf.severity == "high"),
                    remediation=(
                        "Replace the package with one using an approved license, "
                        "or obtain explicit waiver from the architect."
                    ),
                )
            )

    # ── Gate 4: Provenance ───────────────────────────────────────────────
    require_ver = getattr(att, "require_model_version", False)
    if commit_msg:
        print("  [ATTEST] Provenance check...")
        pf = _check_provenance(commit_msg, require_ver)
        if pf:
            all_findings.append(pf)

    # ── Determine pass/fail ──────────────────────────────────────────────
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    block_sev = getattr(config.thresholds, "block_on_severity", "critical")
    block_rank = sev_order.get(block_sev, 0)

    blocking = [f for f in all_findings if sev_order.get(f.severity, 3) <= block_rank]

    return AttestationReport(
        findings=all_findings,
        complexity_violations=sum(1 for f in all_findings if f.gate == "complexity"),
        sensitive_areas_flagged=sum(1 for f in all_findings if f.gate == "sensitive_area"),
        license_issues=sum(1 for f in all_findings if f.gate == "license"),
        provenance_valid=not any(f.gate == "provenance" for f in all_findings),
        overall_passed=len(blocking) == 0,
    )


def render_text(report: AttestationReport) -> str:
    status = "PASSED" if report.overall_passed else "FAILED"
    sep = "-" * 65
    lines = [
        sep,
        "  CODE GENERATION ATTESTATION GATE",
        sep,
        f"  Complexity violations : {report.complexity_violations}",
        f"  Sensitive areas flagged: {report.sensitive_areas_flagged}",
        f"  License issues        : {report.license_issues}",
        f"  Provenance valid      : {'YES' if report.provenance_valid else 'NO'}",
        sep,
        f"  ATTESTATION: {status}",
    ]

    human_review = [f for f in report.findings if f.requires_human_review]
    if human_review:
        lines.append("")
        lines.append(f"  MANDATORY HUMAN REVIEW required for {len(human_review)} finding(s):")
        for f in human_review[:5]:
            lines.append(f"    [{f.severity.upper()}] {f.file}:{f.line} — {f.message}")
        if len(human_review) > 5:
            lines.append(f"    ... and {len(human_review) - 5} more")

    if report.findings:
        lines.append("")
        lines.append("  All findings:")
        for f in sorted(report.findings, key=lambda x: (x.severity, x.file, x.line)):
            lines.append(
                f"    [{f.severity.upper():8}] [{f.gate}] {f.file}:{f.line} "
                f"({f.function_name}) — {f.message}"
            )

    lines.append(sep)
    return "\n".join(lines)



def render_vscode(report: AttestationReport) -> str:
    """Output in VS Code problem matcher format: file:line:col: severity: [ATTEST] message"""
    severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "info"}
    lines = []
    for f in sorted(report.findings, key=lambda x: (x.file, x.line)):
        vsc_sev = severity_map.get(f.severity, "warning")
        lines.append(f"{f.file}:{f.line}:0: {vsc_sev}: [ATTEST] {f.message}")
    return "\n".join(lines)


def render_json(report: AttestationReport) -> str:
    return json.dumps(asdict(report), indent=2)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run Code Generation Attestation Gate")
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--config", default="governance.yaml")
    parser.add_argument("--commit-msg", default="")
    parser.add_argument("--output", choices=["text", "json", "vscode"], default="text")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "any"], default="critical")
    args = parser.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from core.validators.config_validator import ConfigValidationError, load_and_validate

    try:
        cfg = load_and_validate(args.config)
    except ConfigValidationError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    project_root = args.paths[0] if len(args.paths) == 1 and os.path.isdir(args.paths[0]) else "."
    report = run_attestation(args.paths, cfg, args.commit_msg, project_root)

    if args.output == "json":
        print(render_json(report))
    elif args.output == "vscode":
        print(render_vscode(report))
    else:
        print(render_text(report))

    fail_ranks = {"critical": 0, "high": 1, "medium": 2, "any": 3}
    fail_rank = fail_ranks.get(args.fail_on, 0)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    should_fail = any(sev_order.get(f.severity, 3) <= fail_rank for f in report.findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
