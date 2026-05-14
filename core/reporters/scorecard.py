"""
Governance Scorecard — aggregates all scan results into a structured report.
Outputs JSON (stored as CI artifact) and a human-readable text summary.
Sends escalation notifications when configured thresholds are breached.
"""

import json
import os
import smtplib
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional


@dataclass
class ScanSummary:
    scanner: str
    passed: bool
    finding_count: int
    critical: int
    high: int
    medium: int
    low: int
    findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Scorecard:
    team_name: str
    platform: str
    stage: str                       # pre-commit | pr | pipeline
    timestamp: str
    build_ref: str
    pr_number: Optional[str]
    overall_passed: bool
    baa_verified: bool
    scans: List[ScanSummary]
    escalated_to: List[str]
    block_reason: Optional[str]


def _count_by_severity(findings: List[Dict], severity_field: str = "severity") -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get(severity_field, "low").lower()
        # normalize semgrep's "error"/"warning" to critical/high
        if sev == "error":
            sev = "critical"
        elif sev == "warning":
            sev = "high"
        if sev in counts:
            counts[sev] += 1
        else:
            counts["low"] += 1
    return counts


def build_scorecard(
    team_name: str,
    platform: str,
    stage: str,
    baa_verified: bool,
    block_severity: str,
    escalate_severity: str,
    architect_email: str,
    phi_findings: List[Any],
    sast_findings: List[Any],
    dep_findings: List[Any],
    pr_number: Optional[str] = None,
    build_ref: str = "",
) -> Scorecard:

    severity_order = ["critical", "high", "medium", "low"]
    block_rank = severity_order.index(block_severity) if block_severity in severity_order else 0
    escalate_rank = severity_order.index(escalate_severity) if escalate_severity in severity_order else 1

    def to_dicts(findings) -> List[Dict]:
        result = []
        for f in findings:
            result.append(asdict(f) if hasattr(f, "__dataclass_fields__") else dict(f))
        return result

    phi_dicts = to_dicts(phi_findings)
    sast_dicts = to_dicts(sast_findings)
    dep_dicts = to_dicts(dep_findings)

    def make_summary(scanner, dicts):
        counts = _count_by_severity(dicts)
        breaches = sum(
            count for i, (sev, count) in enumerate(counts.items()) if i <= block_rank
        )
        return ScanSummary(
            scanner=scanner,
            passed=breaches == 0,
            finding_count=len(dicts),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            findings=dicts,
        )

    phi_summary = make_summary("phi_detector", phi_dicts)
    sast_summary = make_summary("sast", sast_dicts)
    dep_summary = make_summary("dependency_scan", dep_dicts)

    all_scans = [phi_summary, sast_summary, dep_summary]
    overall_passed = all(s.passed for s in all_scans)

    block_reason = None
    if not overall_passed:
        failed = [s.scanner for s in all_scans if not s.passed]
        block_reason = f"Blocking findings in: {', '.join(failed)}"

    # Determine if escalation is needed (findings at escalate_severity but below block_severity)
    escalated_to = []
    total_high = sum(s.high for s in all_scans)
    if total_high > 0 and architect_email:
        escalated_to.append(architect_email)

    return Scorecard(
        team_name=team_name,
        platform=platform,
        stage=stage,
        timestamp=datetime.now(timezone.utc).isoformat(),
        build_ref=build_ref or os.environ.get("GITHUB_SHA", os.environ.get("BITBUCKET_COMMIT", "local")),
        pr_number=pr_number,
        overall_passed=overall_passed,
        baa_verified=baa_verified,
        scans=all_scans,
        escalated_to=escalated_to,
        block_reason=block_reason,
    )


def render_text(card: Scorecard) -> str:
    width = 65
    sep = "─" * width
    status = "PASSED" if card.overall_passed else "FAILED"
    baa_status = "VERIFIED" if card.baa_verified else "NOT VERIFIED ⚠"

    lines = [
        sep,
        f"  HEALTHCARE AI GOVERNANCE SCORECARD",
        sep,
        f"  Team      : {card.team_name}",
        f"  Platform  : {card.platform}",
        f"  Stage     : {card.stage}",
        f"  Build     : {card.build_ref[:12]}",
        f"  PR        : {card.pr_number or 'N/A'}",
        f"  Timestamp : {card.timestamp}",
        f"  BAA       : {baa_status}",
        sep,
    ]

    for scan in card.scans:
        scan_status = "PASS" if scan.passed else "FAIL"
        lines.append(
            f"  [{scan_status}] {scan.scanner:<22} "
            f"C:{scan.critical}  H:{scan.high}  M:{scan.medium}  L:{scan.low}"
        )

    lines.append(sep)
    lines.append(f"  OVERALL: {status}")

    if card.block_reason:
        lines.append(f"  BLOCKED: {card.block_reason}")

    if card.escalated_to:
        lines.append(f"  ESCALATED TO: {', '.join(card.escalated_to)}")

    if not card.baa_verified:
        lines.append("")
        lines.append("  ACTION REQUIRED: Confirm a signed BAA exists with your")
        lines.append("  AI vendor before using AI tools with any PHI examples.")

    lines.append(sep)
    return "\n".join(lines)


def render_json(card: Scorecard) -> str:
    return json.dumps(asdict(card), indent=2)


def save_scorecard(card: Scorecard, output_dir: str = ".governance/scorecards"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"scorecard_{ts}.json")
    text_path = os.path.join(output_dir, f"scorecard_{ts}.txt")

    with open(json_path, "w") as f:
        f.write(render_json(card))
    with open(text_path, "w") as f:
        f.write(render_text(card))

    print(f"Scorecard saved: {json_path}")
    return json_path, text_path


def send_escalation_email(
    card: Scorecard,
    smtp_host: str = "",
    smtp_port: int = 587,
    from_addr: str = "governance-bot@company.com",
):
    """Send escalation email if SMTP is configured via environment variables."""
    smtp_host = smtp_host or os.environ.get("GOVERNANCE_SMTP_HOST", "")
    if not smtp_host or not card.escalated_to:
        return

    body = render_text(card)
    msg = MIMEText(body)
    msg["Subject"] = f"[GOVERNANCE] {card.team_name} — {card.stage} findings require attention"
    msg["From"] = from_addr
    msg["To"] = ", ".join(card.escalated_to)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.sendmail(from_addr, card.escalated_to, msg.as_string())
        print(f"Escalation email sent to {card.escalated_to}")
    except Exception as e:
        print(f"WARNING: Could not send escalation email: {e}", file=sys.stderr)
