"""
Main CLI entry point for the Healthcare AI Governance Framework.

Usage:
  python -m core.run_checks --stage pre-commit --paths src/
  python -m core.run_checks --stage pr --paths src/ --pr-number 42
  python -m core.run_checks --stage pipeline --paths src/ --build-ref abc123

Exit codes:
  0 — all checks passed
  1 — blocking findings detected (commit/PR/pipeline should be stopped)
  2 — configuration error
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.reporters.scorecard import build_scorecard, render_text, save_scorecard, send_escalation_email
from core.scanners.dependency_scanner import scan as dep_scan
from core.scanners.phi_detector import scan_paths as phi_scan
from core.scanners.sast_runner import run_full_scan as sast_scan
from core.validators.config_validator import ConfigValidationError, load_and_validate


def run(stage: str, paths: list, config_path: str, pr_number: str = None, build_ref: str = ""):
    # ── Load and validate config ──────────────────────────────────────────
    try:
        cfg = load_and_validate(config_path)
    except ConfigValidationError as e:
        print(f"\nCONFIGURATION ERROR:\n{e}", file=sys.stderr)
        sys.exit(2)

    print(f"\n{'='*65}")
    print(f"  Healthcare AI Governance — {stage.upper()} stage")
    print(f"  Team: {cfg.team.name} | Platform: {cfg.team.platform}")
    print(f"{'='*65}\n")

    if not cfg.baa.verified:
        print("WARNING: BAA not verified in governance.yaml.")
        print("         Ensure a signed BAA exists with your AI vendor.\n")

    phi_findings = []
    sast_findings = []
    dep_findings = []

    project_root = paths[0] if len(paths) == 1 and os.path.isdir(paths[0]) else "."

    # ── PRE-COMMIT stage ─────────────────────────────────────────────────
    if stage == "pre-commit":
        if cfg.pre_commit.phi_detection:
            print("Running PHI detection...")
            phi_findings = phi_scan(
                paths,
                cfg.phi_patterns.custom_identifiers,
                cfg.phi_patterns.exclude_paths,
            )
            _print_scan_result("PHI Detection", phi_findings, "severity")

        if cfg.pre_commit.sast:
            print("Running SAST (HIPAA rules)...")
            sast_findings = sast_scan(paths, include_owasp=False)
            _print_scan_result("SAST", sast_findings, "severity")

    # ── PR GATE stage ────────────────────────────────────────────────────
    elif stage == "pr":
        if cfg.pr_gate.sast:
            print("Running SAST (HIPAA + OWASP)...")
            sast_findings = sast_scan(paths, include_owasp=True)
            _print_scan_result("SAST", sast_findings, "severity")

        if cfg.pr_gate.hipaa_checks:
            print("Running PHI detection...")
            phi_findings = phi_scan(
                paths,
                cfg.phi_patterns.custom_identifiers,
                cfg.phi_patterns.exclude_paths,
            )
            _print_scan_result("PHI Detection", phi_findings, "severity")

        if cfg.pr_gate.dependency_scan:
            print("Running dependency CVE scan...")
            dep_findings = dep_scan(project_root, cfg.team.tech_stack)
            _print_scan_result("Dependencies", dep_findings, "severity")

        if cfg.pr_gate.clinical_review_required:
            _check_clinical_triggers(paths, cfg.clinical_keywords, cfg.team.clinical_reviewers)

    # ── PIPELINE stage ───────────────────────────────────────────────────
    elif stage == "pipeline":
        print("Running full scan suite...")
        sast_findings = sast_scan(paths, include_owasp=True)
        phi_findings = phi_scan(paths, cfg.phi_patterns.custom_identifiers, cfg.phi_patterns.exclude_paths)
        dep_findings = dep_scan(project_root, cfg.team.tech_stack)

    # ── Build and output scorecard ────────────────────────────────────────
    card = build_scorecard(
        team_name=cfg.team.name,
        platform=cfg.team.platform,
        stage=stage,
        baa_verified=cfg.baa.verified,
        block_severity=cfg.thresholds.block_on_severity,
        escalate_severity=cfg.thresholds.escalate_on_severity,
        architect_email=cfg.team.architect,
        phi_findings=phi_findings,
        sast_findings=sast_findings,
        dep_findings=dep_findings,
        pr_number=pr_number,
        build_ref=build_ref,
    )

    print(render_text(card))

    if stage == "pipeline" and cfg.pipeline_gate.compliance_scorecard:
        save_scorecard(card)

    send_escalation_email(card)

    sys.exit(0 if card.overall_passed else 1)


def _print_scan_result(name: str, findings: list, severity_field: str):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = getattr(f, severity_field, "low").lower()
        if sev in ("error",):
            sev = "critical"
        elif sev in ("warning",):
            sev = "high"
        counts[sev] = counts.get(sev, 0) + 1

    total = len(findings)
    status = "ISSUES FOUND" if total > 0 else "CLEAN"
    print(f"  {name}: {status} — C:{counts['critical']} H:{counts['high']} M:{counts['medium']} L:{counts['low']}")


def _check_clinical_triggers(paths: list, keywords: list, reviewers: list):
    if not keywords:
        return

    triggered_files = []
    for path in paths:
        if os.path.isfile(path):
            files = [path]
        else:
            files = []
            for root, _, fnames in os.walk(path):
                for fname in fnames:
                    files.append(os.path.join(root, fname))

        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                if any(kw.lower() in content for kw in keywords):
                    triggered_files.append(fpath)
            except OSError:
                pass

    if triggered_files:
        print(f"\n  CLINICAL REVIEW REQUIRED for {len(triggered_files)} file(s):")
        for f in triggered_files[:5]:
            print(f"    {f}")
        if len(triggered_files) > 5:
            print(f"    ... and {len(triggered_files) - 5} more")
        if reviewers:
            print(f"\n  Assign review to: {', '.join(reviewers)}")
        else:
            print("\n  WARNING: No clinical_reviewers configured in governance.yaml")


def main():
    parser = argparse.ArgumentParser(description="Healthcare AI Governance — run scan checks")
    parser.add_argument("--stage", required=True, choices=["pre-commit", "pr", "pipeline"])
    parser.add_argument("--paths", nargs="+", required=True, help="Files or directories to scan")
    parser.add_argument("--config", default="governance.yaml", help="Path to governance.yaml")
    parser.add_argument("--pr-number", default=None)
    parser.add_argument("--build-ref", default="")
    args = parser.parse_args()

    run(
        stage=args.stage,
        paths=args.paths,
        config_path=args.config,
        pr_number=args.pr_number,
        build_ref=args.build_ref,
    )


if __name__ == "__main__":
    main()
