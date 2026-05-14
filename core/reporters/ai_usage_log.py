"""
AI Usage Log

Appends a structured entry to .governance/ai-usage-log.json for every PR scan.
Over time this builds a searchable audit trail of:
  - Which AI tools each team is using
  - How much of each PR's code is AI-generated
  - Whether AI output is being reviewed before merge
  - Trends across teams and time

The log file is designed to be committed to a central governance repo (or
stored as a CI artifact) so architects can query across all teams.
"""

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from core.scanners.ai_attribution_scanner import AttributionReport


LOG_PATH = os.path.join('.governance', 'ai-usage-log.json')


def _load_log(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def append_entry(
    report: AttributionReport,
    team_name: str,
    platform: str,
    build_ref: str,
    stage: str,
) -> dict:
    """Append one entry to the AI usage log and return the entry dict."""
    entry = {
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "team":                    team_name,
        "platform":                platform,
        "stage":                   stage,
        "build_ref":               build_ref[:12],
        "pr_number":               report.pr_number,
        "base_branch":             report.base_branch,
        "total_commits":           report.total_commits,
        "commits_without_tag":     report.commits_without_tag,
        "tools_declared":          report.all_tools_used,
        "tools_auto_detected":     report.auto_detected_tools,
        "pr_template_completed":   report.pr_template_completed,
        "estimated_ai_percentage": report.estimated_ai_percentage,
        "developer_reviewed_count": report.developer_reviewed_count,
        "risk_level":              report.risk_level,
        "risk_reasons":            report.risk_reasons,
        "commit_detail": [
            {
                "hash":             c.commit_hash,
                "author":           c.author,
                "subject":          c.subject[:80],
                "declared_tools":   c.declared_tools,
                "auto_detected":    c.auto_detected_tools,
                "reviewed":         c.developer_reviewed,
                "missing_tag":      c.missing_tag,
            }
            for c in report.commits
        ],
    }

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    log = _load_log(LOG_PATH)
    log.append(entry)

    with open(LOG_PATH, 'w') as f:
        json.dump(log, f, indent=2)

    return entry


def render_summary(log_path: str = LOG_PATH, last_n: int = 30) -> str:
    """Generate a human-readable summary of recent AI usage log entries."""
    entries = _load_log(log_path)
    if not entries:
        return "AI usage log is empty."

    recent = entries[-last_n:]
    width = 65
    sep = '─' * width
    lines = [
        sep,
        '  AI USAGE LOG SUMMARY',
        f'  {len(entries)} total entries | showing last {len(recent)}',
        sep,
    ]

    # Aggregate stats
    all_tools: dict[str, int] = {}
    missing_tag_total = 0
    unreviewed_ai_total = 0
    risk_counts: dict[str, int] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

    for e in recent:
        for tool in e.get('tools_declared', []):
            all_tools[tool] = all_tools.get(tool, 0) + 1
        missing_tag_total += e.get('commits_without_tag', 0)
        reviewed = e.get('developer_reviewed_count', 0)
        total = e.get('total_commits', 0)
        unreviewed_ai_total += max(0, total - reviewed)
        risk = e.get('risk_level', 'low')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    lines += [
        '  TOOL USAGE (last {} entries):'.format(len(recent)),
    ]
    for tool, count in sorted(all_tools.items(), key=lambda x: -x[1]):
        bar = '█' * min(count, 20)
        lines.append(f'  {tool:<15} {bar} {count}')

    lines += [
        sep,
        f'  Commits missing AI tag : {missing_tag_total}',
        f'  Unreviewed AI commits  : {unreviewed_ai_total}',
        f'  Risk distribution      : '
        f'C:{risk_counts["critical"]} H:{risk_counts["high"]} '
        f'M:{risk_counts["medium"]} L:{risk_counts["low"]}',
        sep,
        '  RECENT ENTRIES:',
    ]

    for e in reversed(recent[-10:]):
        ts = e.get('timestamp', '')[:16]
        team = e.get('team', '?')
        pr = e.get('pr_number', '?')
        tools = ', '.join(e.get('tools_declared', ['none'])) or '—'
        risk = e.get('risk_level', '?').upper()
        lines.append(f'  {ts}  {team:<20} PR#{pr:<5} [{risk}]  {tools}')

    lines.append(sep)
    return '\n'.join(lines)
