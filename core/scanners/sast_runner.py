"""
SAST Runner — wraps Semgrep with the HIPAA ruleset + OWASP rules.
Falls back gracefully if semgrep is not installed.
"""

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

HIPAA_RULESET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "hipaa_checks", "hipaa_ruleset.yaml"
)

OWASP_SEMGREP_RULESETS = [
    "p/owasp-top-ten",
    "p/secrets",
    "p/sql-injection",
]


@dataclass
class SASTFinding:
    file: str
    line_number: int
    rule_id: str
    message: str
    severity: str
    category: str
    fix_hint: str


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _parse_semgrep_output(raw: dict) -> List[SASTFinding]:
    findings = []
    for result in raw.get("results", []):
        meta = result.get("extra", {}).get("metadata", {})
        findings.append(
            SASTFinding(
                file=result.get("path", ""),
                line_number=result.get("start", {}).get("line", 0),
                rule_id=result.get("check_id", ""),
                message=result.get("extra", {}).get("message", ""),
                severity=result.get("extra", {}).get("severity", "WARNING").lower(),
                category=meta.get("category", "security"),
                fix_hint=meta.get("fix", ""),
            )
        )
    return findings


def run_hipaa_rules(paths: List[str]) -> List[SASTFinding]:
    """Run the custom HIPAA semgrep ruleset against specified paths."""
    if not semgrep_available():
        print("WARNING: semgrep not found. Install with: pip install semgrep", file=sys.stderr)
        return []

    ruleset = os.path.abspath(HIPAA_RULESET_PATH)
    if not os.path.exists(ruleset):
        print(f"WARNING: HIPAA ruleset not found at {ruleset}", file=sys.stderr)
        return []

    cmd = [
        "semgrep",
        "--config", ruleset,
        "--json",
        "--quiet",
    ] + paths

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
        return _parse_semgrep_output(raw)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"WARNING: HIPAA SAST scan failed: {e}", file=sys.stderr)
        return []


def run_owasp_rules(paths: List[str]) -> List[SASTFinding]:
    """Run OWASP Top 10 semgrep rulesets."""
    if not semgrep_available():
        return []

    all_findings = []
    for ruleset in OWASP_SEMGREP_RULESETS:
        cmd = [
            "semgrep",
            "--config", ruleset,
            "--json",
            "--quiet",
        ] + paths

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
            all_findings.extend(_parse_semgrep_output(raw))
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

    return all_findings


def run_full_scan(paths: List[str], include_owasp: bool = True) -> List[SASTFinding]:
    findings = run_hipaa_rules(paths)
    if include_owasp:
        findings.extend(run_owasp_rules(paths))
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def severity_rank(s: str) -> int:
    return {"error": 0, "critical": 0, "warning": 1, "high": 1, "info": 2, "medium": 2, "low": 3}.get(s, 4)


def main():
    import argparse
    from dataclasses import asdict

    parser = argparse.ArgumentParser(description="Run SAST scan (HIPAA + OWASP)")
    parser.add_argument("paths", nargs="+", help="Files or directories to scan")
    parser.add_argument("--hipaa-only", action="store_true", help="Run HIPAA rules only")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["error", "warning", "all"], default="error")
    args = parser.parse_args()

    if not semgrep_available():
        print("ERROR: semgrep is required. Install with: pip install semgrep")
        sys.exit(2)

    findings = run_full_scan(args.paths, include_owasp=not args.hipaa_only)
    findings.sort(key=lambda f: (severity_rank(f.severity), f.file, f.line_number))

    if args.output == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("SAST scan: PASSED — no findings.")
        else:
            print(f"\nSAST FINDINGS ({len(findings)} total):\n{'─'*60}")
            for f in findings:
                print(f"[{f.severity.upper()}] {f.file}:{f.line_number} — {f.rule_id}")
                print(f"  {f.message}")
                if f.fix_hint:
                    print(f"  Fix: {f.fix_hint}")
                print()

    fail_ranks = {"error": 0, "warning": 1, "all": 3}
    fail_at = fail_ranks.get(args.fail_on, 0)
    should_fail = any(severity_rank(f.severity) <= fail_at for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
