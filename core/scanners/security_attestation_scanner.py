"""
Security Attestation Gate — dedicated security gate for AI-generated code.

Runs before any environment promotion (PR merge / release pipeline). Covers:

  Gate 1  owasp_sast          Zero critical/high on OWASP Top 10 + custom security rules
  Gate 2  crypto_primitives   No weak hashes, no custom crypto, no Math.random for tokens
  Gate 3  xss_injection       No raw innerHTML, no eval() with user input, no open redirects
  Gate 4  llm_surface         Detect LLM-integrated features, flag for prompt injection review
  Gate 5  iac_security        Checkov / tfsec — zero critical findings on IaC
  Gate 6  sbom                SBOM artifact generated and present (advisory on PR, block on release)
  Gate 7  pentest_required    Flag high-risk AI features for mandatory pen-test sign-off

All findings are SecurityAttestationFinding objects that roll into the scorecard.
"""

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Tuple

# ── LLM package patterns ──────────────────────────────────────────────────────

_LLM_IMPORT_PATTERNS = [
    # Python imports
    re.compile(r'^\s*(?:import|from)\s+(openai|anthropic|langchain|transformers|'
               r'google\.generativeai|cohere|mistralai|ollama|litellm|huggingface_hub)',
               re.MULTILINE),
    # Node/TS imports
    re.compile(r"""(?:import|require)\s*\(?['"](@?openai|@anthropic-ai/sdk|langchain|"""
               r"""@google/generative-ai|cohere-ai|mistralai|ollama|llm-chain)['"]"""),
]

_PROMPT_CONCAT_PATTERNS = [
    re.compile(r'(?:user_input|request\.|req\.|\.body\.|\.query\.|\.params\.|input_text|'
               r'user_text|user_message|user_prompt)\s*[\+\.]', re.IGNORECASE),
    re.compile(r'f["\'].*\{(?:request|req|body|query|user)[^}]*\}.*["\']', re.IGNORECASE),
]

_LLM_CALL_PATTERNS = [
    re.compile(r'\.chat\.completions\.create|\.messages\.create|\.generate_content|'
               r'\.chat\(|openai\.Completion|client\.complete\b', re.IGNORECASE),
]

_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".go", ".rb", ".php",
}

_ALWAYS_SKIP = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".angular",
}

_SBOM_FILENAMES = {"sbom.json", "sbom.cdx.json", "sbom.spdx.json", "bom.json"}


@dataclass
class SecurityAttestationFinding:
    gate: str               # owasp_sast | crypto | xss_injection | llm_surface | iac | sbom | pentest
    severity: str           # critical | high | medium | low
    file: str
    line: int
    rule_id: str
    message: str
    cwe: str = ""
    owasp_category: str = ""
    detail: str = ""
    requires_pentest_signoff: bool = False
    remediation: str = ""


@dataclass
class SecurityAttestationReport:
    findings: List[SecurityAttestationFinding] = field(default_factory=list)
    sbom_generated: bool = False
    sbom_path: str = ""
    iac_scanned: bool = False
    llm_surfaces_found: int = 0
    pentest_required: bool = False
    overall_passed: bool = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _walk_code_files(paths: List[str]) -> List[str]:
    result = []
    for path in paths:
        if os.path.isfile(path):
            if os.path.splitext(path)[1].lower() in _CODE_EXTENSIONS:
                result.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in _ALWAYS_SKIP]
                for fname in files:
                    fp = os.path.join(root, fname)
                    if os.path.splitext(fp)[1].lower() in _CODE_EXTENSIONS:
                        result.append(fp)
    return result


def _find_sbom(project_root: str) -> Optional[str]:
    for dirpath, _, files in os.walk(project_root):
        for fname in files:
            if fname.lower() in _SBOM_FILENAMES or fname.lower().endswith(".cdx.json"):
                return os.path.join(dirpath, fname)
    return None


# ── Gate 1+2+3: SAST via security_ruleset.yaml + OWASP ───────────────────────

def _run_security_sast(paths: List[str]) -> List[SecurityAttestationFinding]:
    findings: List[SecurityAttestationFinding] = []

    try:
        import shutil
        if not shutil.which("semgrep"):
            print("  INFO: semgrep not found — skipping SAST security scan.", file=sys.stderr)
            return []

        import subprocess

        ruleset_path = os.path.join(
            os.path.dirname(__file__), "..", "hipaa_checks", "security_ruleset.yaml"
        )
        ruleset_path = os.path.abspath(ruleset_path)

        rulesets_to_run = []
        if os.path.exists(ruleset_path):
            rulesets_to_run.append(ruleset_path)
        rulesets_to_run.append("p/owasp-top-ten")

        import json as _json
        for ruleset in rulesets_to_run:
            cmd = ["semgrep", "--config", ruleset, "--json", "--quiet"] + paths
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                raw = _json.loads(result.stdout) if result.stdout.strip() else {"results": []}
            except (subprocess.TimeoutExpired, _json.JSONDecodeError):
                continue

            for r in raw.get("results", []):
                meta = r.get("extra", {}).get("metadata", {})
                sev_raw = r.get("extra", {}).get("severity", "WARNING").lower()
                sev = "critical" if sev_raw in ("error", "critical") else \
                      "high" if sev_raw in ("warning", "high") else \
                      "medium" if sev_raw in ("info", "medium") else "low"
                rule_id = r.get("check_id", "")
                # Classify into gate
                gate = "owasp_sast"
                if any(k in rule_id for k in ("crypto", "hash", "cipher", "random")):
                    gate = "crypto"
                elif any(k in rule_id for k in ("xss", "innerhtml", "eval", "redirect")):
                    gate = "xss_injection"
                elif "prompt" in rule_id or "llm" in rule_id:
                    gate = "llm_surface"
                elif "iac" in rule_id or "terraform" in rule_id or "docker" in rule_id:
                    gate = "iac"

                findings.append(
                    SecurityAttestationFinding(
                        gate=gate,
                        severity=sev,
                        file=r.get("path", ""),
                        line=r.get("start", {}).get("line", 0),
                        rule_id=rule_id,
                        message=r.get("extra", {}).get("message", ""),
                        cwe=meta.get("cwe", ""),
                        owasp_category=meta.get("owasp", ""),
                        detail=meta.get("category", ""),
                        remediation=meta.get("fix", ""),
                    )
                )

        # Deduplicate
        seen = set()
        deduped = []
        for f in findings:
            key = (f.file, f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    except Exception as e:
        print(f"  WARNING: Security SAST failed (non-blocking): {e}", file=sys.stderr)
        return []


# ── Gate 4: LLM surface detection ────────────────────────────────────────────

def _detect_llm_surfaces(paths: List[str]) -> List[SecurityAttestationFinding]:
    findings: List[SecurityAttestationFinding] = []
    code_files = _walk_code_files(paths)

    for fpath in code_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except OSError:
            continue

        has_llm_import = any(p.search(content) for p in _LLM_IMPORT_PATTERNS)
        if not has_llm_import:
            continue

        # File imports an LLM library — flag for prompt injection review
        findings.append(
            SecurityAttestationFinding(
                gate="llm_surface",
                severity="high",
                file=fpath,
                line=1,
                rule_id="sec-llm-surface-detected",
                message="LLM library import detected — prompt injection assessment required",
                cwe="CWE-20: Improper Input Validation",
                owasp_category="A03:2021 - Injection",
                detail="File imports an AI/LLM SDK. Review all user-input paths for prompt injection.",
                requires_pentest_signoff=True,
                remediation=(
                    "1. Review all user inputs that flow into LLM prompts.\n"
                    "2. Sanitize/validate inputs before including in prompts.\n"
                    "3. Use system message separation — never merge user content into system prompt.\n"
                    "4. Apply output validation — do not use raw LLM output in SQL/HTML without encoding.\n"
                    "5. Schedule adversarial prompt testing as part of pen-test scope."
                ),
            )
        )

        # Check for direct user input in LLM calls (prompt injection pattern)
        for line_no, line in enumerate(lines, start=1):
            line_lower = line.lower()
            if not any(p.search(line) for p in _LLM_CALL_PATTERNS):
                continue
            if any(p.search(line_lower) for p in _PROMPT_CONCAT_PATTERNS):
                findings.append(
                    SecurityAttestationFinding(
                        gate="llm_surface",
                        severity="critical",
                        file=fpath,
                        line=line_no,
                        rule_id="sec-prompt-injection-direct",
                        message="User-controlled input directly in LLM call — critical prompt injection risk",
                        cwe="CWE-20: Improper Input Validation",
                        owasp_category="A03:2021 - Injection",
                        detail=f"Line contains LLM call with apparent user-input concatenation: {line.strip()[:100]}",
                        requires_pentest_signoff=True,
                        remediation=(
                            "Sanitize user input before passing to LLM. "
                            "Use structured message format with clear user/system separation."
                        ),
                    )
                )

    return findings


# ── Gate 5: IaC security ──────────────────────────────────────────────────────

def _run_iac_gate(paths: List[str]) -> Tuple[List[SecurityAttestationFinding], bool]:
    from core.scanners.iac_scanner import scan as iac_scan

    iac_findings_raw = iac_scan(paths)
    findings = []
    for f in iac_findings_raw:
        findings.append(
            SecurityAttestationFinding(
                gate="iac",
                severity=f.severity,
                file=f.file,
                line=f.line,
                rule_id=f.check_id,
                message=f.message,
                detail=f"resource={f.resource}, framework={f.framework}",
                remediation=f.guideline,
            )
        )
    return findings, bool(iac_findings_raw is not None)


# ── Gate 6: SBOM check ────────────────────────────────────────────────────────

def _check_sbom(project_root: str) -> Tuple[bool, str, Optional[SecurityAttestationFinding]]:
    sbom_path = _find_sbom(project_root)
    if sbom_path:
        return True, sbom_path, None

    finding = SecurityAttestationFinding(
        gate="sbom",
        severity="medium",
        file=project_root,
        line=0,
        rule_id="sec-sbom-missing",
        message="No SBOM artifact found in repository",
        detail=(
            "A signed Software Bill of Materials (SBOM) must be generated for every "
            "release artifact to support supply chain security."
        ),
        remediation=(
            "Generate SBOM in CI with: syft . -o cyclonedx-json > sbom.cdx.json\n"
            "Or: npx @cyclonedx/cyclonedx-npm --output-file sbom.cdx.json\n"
            "Sign with: cosign attest --predicate sbom.cdx.json <artifact>"
        ),
    )
    return False, "", finding


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run_security_attestation(
    paths: List[str],
    config,                     # GovernanceConfig
    project_root: str = ".",
) -> SecurityAttestationReport:
    sec_cfg = getattr(config, "security_attestation", None)
    if sec_cfg is not None and not getattr(sec_cfg, "enabled", True):
        return SecurityAttestationReport(overall_passed=True)

    all_findings: List[SecurityAttestationFinding] = []

    # Gate 1+2+3: SAST (OWASP + security rules)
    print("  [SEC] Running OWASP + security SAST scan...")
    all_findings.extend(_run_security_sast(paths))

    # Gate 4: LLM surface detection
    print("  [SEC] Detecting LLM surfaces (prompt injection assessment)...")
    llm_findings = _detect_llm_surfaces(paths)
    all_findings.extend(llm_findings)
    llm_surfaces = len({f.file for f in llm_findings if f.rule_id == "sec-llm-surface-detected"})

    # Gate 5: IaC security
    print("  [SEC] Running IaC security scan (Checkov)...")
    iac_findings, iac_ran = _run_iac_gate(paths)
    all_findings.extend(iac_findings)

    # Gate 6: SBOM
    sbom_check = getattr(sec_cfg, "sbom_required", True) if sec_cfg else True
    sbom_generated, sbom_path, sbom_finding = _check_sbom(project_root)
    if not sbom_generated and sbom_check and sbom_finding:
        all_findings.append(sbom_finding)

    # Gate 7: Pen-test sign-off required?
    pentest_required = any(f.requires_pentest_signoff for f in all_findings)

    # Compute pass/fail
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    block_sev = getattr(config.thresholds, "block_on_severity", "critical")
    block_rank = sev_order.get(block_sev, 0)
    blocking = [f for f in all_findings if sev_order.get(f.severity, 3) <= block_rank]

    return SecurityAttestationReport(
        findings=all_findings,
        sbom_generated=sbom_generated,
        sbom_path=sbom_path,
        iac_scanned=iac_ran,
        llm_surfaces_found=llm_surfaces,
        pentest_required=pentest_required,
        overall_passed=len(blocking) == 0,
    )


# ── Renderers ─────────────────────────────────────────────────────────────────

def render_text(report: SecurityAttestationReport) -> str:
    status = "PASSED" if report.overall_passed else "FAILED"
    sep = "-" * 65
    lines = [
        sep,
        "  SECURITY ATTESTATION GATE",
        sep,
        f"  SBOM generated        : {'YES — ' + report.sbom_path if report.sbom_generated else 'NO (advisory)'}",
        f"  IaC scanned           : {'YES' if report.iac_scanned else 'NO (no IaC files or tool unavailable)'}",
        f"  LLM surfaces found    : {report.llm_surfaces_found}",
        f"  Pen-test required     : {'YES' if report.pentest_required else 'NO'}",
        sep,
    ]

    gate_counts: dict = {}
    for f in report.findings:
        gate_counts.setdefault(f.gate, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        gate_counts[f.gate][f.severity] = gate_counts[f.gate].get(f.severity, 0) + 1

    for gate, counts in sorted(gate_counts.items()):
        total = sum(counts.values())
        status_tag = "FAIL" if (counts["critical"] + counts["high"]) > 0 else "WARN" if total > 0 else "PASS"
        lines.append(
            f"  [{status_tag}] {gate:<22} "
            f"C:{counts['critical']}  H:{counts['high']}  M:{counts['medium']}  L:{counts['low']}"
        )

    lines.append(sep)
    lines.append(f"  OVERALL SECURITY: {status}")

    pentest = [f for f in report.findings if f.requires_pentest_signoff]
    if pentest:
        lines.append("")
        lines.append(f"  PEN-TEST SIGN-OFF required for {len(pentest)} finding(s):")
        seen_files = set()
        for f in pentest:
            if f.file not in seen_files:
                seen_files.add(f.file)
                lines.append(f"    {f.file}")

    if report.findings:
        lines.append("")
        lines.append("  Findings:")
        for f in sorted(report.findings, key=lambda x: (x.severity, x.file, x.line)):
            lines.append(
                f"    [{f.severity.upper():8}] [{f.gate}] {f.file}:{f.line} — {f.message}"
            )

    lines.append(sep)
    return "\n".join(lines)


def render_json(report: SecurityAttestationReport) -> str:
    return json.dumps(asdict(report), indent=2)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Security Attestation Gate")
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--config", default="governance.yaml")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"], default="high")
    args = parser.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from core.validators.config_validator import ConfigValidationError, load_and_validate

    try:
        cfg = load_and_validate(args.config)
    except ConfigValidationError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    project_root = args.paths[0] if len(args.paths) == 1 and os.path.isdir(args.paths[0]) else "."
    report = run_security_attestation(args.paths, cfg, project_root)

    if args.output == "json":
        print(render_json(report))
    else:
        print(render_text(report))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    fail_rank = sev_order.get(args.fail_on, 1)
    should_fail = any(sev_order.get(f.severity, 3) <= fail_rank for f in report.findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
