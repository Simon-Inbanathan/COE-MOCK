"""
AI Attribution Scanner

Aggregates three signal sources to determine AI tool involvement in a PR:

  Signal 1 — Commit message tags    [ai:claude,reviewed]  (enforced via hook)
  Signal 2 — Co-Authored-By lines   auto-added by Claude Code, Copilot Enterprise
  Signal 3 — PR description         structured declaration from PR template

Produces a per-PR AttributionReport used by the scorecard and usage log.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional


# ── Known AI Co-Authored-By signatures ───────────────────────────────────────
CO_AUTHOR_PATTERNS = {
    "claude":   re.compile(r'claude', re.I),
    "copilot":  re.compile(r'copilot|github-actions\[bot\]', re.I),
    "gemini":   re.compile(r'gemini', re.I),
    "codeium":  re.compile(r'codeium', re.I),
    "tabnine":  re.compile(r'tabnine', re.I),
}

AI_TAG_PATTERN    = re.compile(r'\[ai:([\w,\s]+)\]', re.IGNORECASE)
REVIEWED_PATTERN  = re.compile(r'\[ai:[^\]]*reviewed[^\]]*\]', re.IGNORECASE)
CO_AUTHOR_PATTERN = re.compile(r'^Co-Authored-By:\s*(.+)$', re.MULTILINE | re.IGNORECASE)

# Tokens in PR body that indicate the PR template was completed
PR_TEMPLATE_TOOL_PATTERNS = {
    "claude":   re.compile(r'-\s*\[x\]\s*Claude', re.I),
    "copilot":  re.compile(r'-\s*\[x\]\s*GitHub Copilot', re.I),
    "cursor":   re.compile(r'-\s*\[x\]\s*Cursor', re.I),
    "windsurf": re.compile(r'-\s*\[x\]\s*Windsurf', re.I),
    "chatgpt":  re.compile(r'-\s*\[x\]\s*ChatGPT', re.I),
    "none":     re.compile(r'-\s*\[x\]\s*No AI tools', re.I),
}
PR_REVIEWED_PATTERN     = re.compile(r'reviewed[^:\n]*:\*{0,2}\s*(yes|true)', re.I)
PR_PERCENTAGE_PATTERN   = re.compile(r'%\s*AI-generated[^:\n]*:\*{0,2}\s*(\d{1,3})', re.I)


@dataclass
class CommitAttribution:
    commit_hash: str
    subject: str
    author: str
    declared_tools: list[str]         # from [ai:...] tag
    auto_detected_tools: list[str]    # from Co-Authored-By
    developer_reviewed: bool          # [ai:...,reviewed] or explicit review tag
    missing_tag: bool                 # commit had no [ai:] tag at all
    co_author_lines: list[str]


@dataclass
class AttributionReport:
    pr_number: Optional[str]
    base_branch: str
    total_commits: int
    commits_without_tag: int
    all_tools_used: list[str]         # union across all commits + PR template
    auto_detected_tools: list[str]    # tools caught via Co-Authored-By only
    developer_reviewed_count: int     # commits where developer confirmed review
    pr_template_tools: list[str]      # tools declared in PR description
    pr_template_completed: bool
    estimated_ai_percentage: Optional[int]
    commits: list[CommitAttribution]
    risk_level: str                   # low | medium | high | critical
    risk_reasons: list[str]


def _run_git(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ['git'] + args, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ''


def _parse_commit_log(raw: str) -> list[CommitAttribution]:
    if not raw:
        return []

    commits = []
    # Format: HASH|||SUBJECT|||BODY|||AUTHOR
    for block in raw.split('---COMMIT_SEP---'):
        block = block.strip()
        if not block:
            continue

        parts = block.split('|||', 3)
        if len(parts) < 4:
            continue

        hash_, subject, body, author = parts
        full_text = subject + '\n' + body

        # Signal 1: [ai:...] tag
        tag_match = AI_TAG_PATTERN.search(full_text)
        declared_tools = []
        missing_tag = True
        if tag_match:
            missing_tag = False
            declared_tools = [
                t.strip().lower()
                for t in tag_match.group(1).split(',')
                if t.strip().lower() not in ('reviewed',)
            ]

        # Signal 2: Co-Authored-By
        co_author_lines = CO_AUTHOR_PATTERN.findall(body)
        auto_detected = []
        for line in co_author_lines:
            for tool, pattern in CO_AUTHOR_PATTERNS.items():
                if pattern.search(line) and tool not in auto_detected:
                    auto_detected.append(tool)

        # Review flag
        reviewed = bool(REVIEWED_PATTERN.search(full_text))

        commits.append(CommitAttribution(
            commit_hash=hash_[:8],
            subject=subject.strip(),
            author=author.strip(),
            declared_tools=declared_tools,
            auto_detected_tools=auto_detected,
            developer_reviewed=reviewed,
            missing_tag=missing_tag,
            co_author_lines=co_author_lines,
        ))

    return commits


def scan_commits(base_branch: str = 'main') -> list[CommitAttribution]:
    """Read all commits in current branch not yet merged into base_branch."""
    # Use the git log format: hash|||subject|||body|||author, separated by sentinel
    raw = _run_git([
        'log', f'{base_branch}..HEAD',
        '--format=---COMMIT_SEP---%n%H|||%s|||%b|||%an',
    ])
    return _parse_commit_log(raw)


def scan_pr_body(pr_body: str) -> tuple[list[str], bool, Optional[int]]:
    """Extract tool declarations from a PR description.
    Returns (tools_declared, was_reviewed, ai_percentage).
    """
    tools = []
    for tool, pattern in PR_TEMPLATE_TOOL_PATTERNS.items():
        if pattern.search(pr_body):
            tools.append(tool)

    reviewed = bool(PR_REVIEWED_PATTERN.search(pr_body))

    pct_match = PR_PERCENTAGE_PATTERN.search(pr_body)
    percentage = int(pct_match.group(1)) if pct_match else None

    return tools, reviewed, percentage


def _calculate_risk(
    commits: list[CommitAttribution],
    pr_tools: list[str],
    pr_template_completed: bool,
    estimated_pct: Optional[int],
) -> tuple[str, list[str]]:
    reasons = []

    commits_with_ai = [
        c for c in commits
        if c.declared_tools or c.auto_detected_tools
    ]
    missing_tags = [c for c in commits if c.missing_tag]
    unreviewed_ai = [
        c for c in commits_with_ai if not c.developer_reviewed
    ]

    if missing_tags:
        pct = len(missing_tags) / max(len(commits), 1) * 100
        reasons.append(f"{len(missing_tags)} commit(s) ({pct:.0f}%) missing AI attribution tag")

    if commits_with_ai and not pr_template_completed:
        reasons.append("AI tools detected in commits but PR template not completed")

    if unreviewed_ai:
        reasons.append(
            f"{len(unreviewed_ai)} AI-generated commit(s) not marked as reviewed"
        )

    if estimated_pct is not None and estimated_pct > 80:
        reasons.append(
            f"Declared AI generation at {estimated_pct}% — high proportion requires careful review"
        )

    # Auto-detected but not declared = shadow AI usage
    auto_only_tools = set()
    for c in commits:
        for tool in c.auto_detected_tools:
            declared_in_any = any(tool in oc.declared_tools for oc in commits)
            if not declared_in_any and tool not in pr_tools:
                auto_only_tools.add(tool)
    if auto_only_tools:
        reasons.append(
            f"AI tools auto-detected but not declared: {sorted(auto_only_tools)}"
        )

    if not reasons:
        return "low", []
    if len(reasons) == 1:
        return "medium", reasons
    if len(reasons) == 2:
        return "high", reasons
    return "critical", reasons


def build_report(
    base_branch: str = 'main',
    pr_number: Optional[str] = None,
    pr_body: str = '',
) -> AttributionReport:
    commits = scan_commits(base_branch)
    pr_tools, pr_reviewed, estimated_pct = scan_pr_body(pr_body)

    pr_template_completed = bool(pr_tools) or bool(PR_REVIEWED_PATTERN.search(pr_body))

    all_tools: set[str] = set(pr_tools)
    auto_detected_global: set[str] = set()
    reviewed_count = 0

    for c in commits:
        all_tools.update(c.declared_tools)
        auto_detected_global.update(c.auto_detected_tools)
        if c.developer_reviewed or pr_reviewed:
            reviewed_count += 1

    # Remove 'none' from tools list if other tools also present
    if len(all_tools) > 1:
        all_tools.discard('none')

    commits_without_tag = sum(1 for c in commits if c.missing_tag)
    risk, reasons = _calculate_risk(commits, pr_tools, pr_template_completed, estimated_pct)

    return AttributionReport(
        pr_number=pr_number,
        base_branch=base_branch,
        total_commits=len(commits),
        commits_without_tag=commits_without_tag,
        all_tools_used=sorted(all_tools),
        auto_detected_tools=sorted(auto_detected_global),
        developer_reviewed_count=reviewed_count,
        pr_template_tools=pr_tools,
        pr_template_completed=pr_template_completed,
        estimated_ai_percentage=estimated_pct,
        commits=commits,
        risk_level=risk,
        risk_reasons=reasons,
    )


def render_text(report: AttributionReport) -> str:
    width = 60
    sep = '─' * width
    lines = [
        sep,
        '  AI ATTRIBUTION REPORT',
        sep,
        f'  PR            : {report.pr_number or "N/A"}',
        f'  Base branch   : {report.base_branch}',
        f'  Total commits : {report.total_commits}',
        f'  Missing tag   : {report.commits_without_tag}',
        f'  Tools used    : {", ".join(report.all_tools_used) or "none declared"}',
        f'  Auto-detected : {", ".join(report.auto_detected_tools) or "none"}',
        f'  Reviewed count: {report.developer_reviewed_count}/{report.total_commits}',
        f'  PR template   : {"Completed" if report.pr_template_completed else "NOT completed"}',
        f'  AI percentage : {report.estimated_ai_percentage if report.estimated_ai_percentage is not None else "not declared"}%',
        f'  Risk level    : {report.risk_level.upper()}',
        sep,
    ]

    if report.risk_reasons:
        lines.append('  ISSUES:')
        for r in report.risk_reasons:
            lines.append(f'    • {r}')
        lines.append(sep)

    lines.append('  COMMIT BREAKDOWN:')
    for c in report.commits:
        tag_status = '✓' if not c.missing_tag else '✗ NO TAG'
        tools = ', '.join(c.declared_tools) or ('auto:' + ','.join(c.auto_detected_tools)) or '—'
        reviewed = '[reviewed]' if c.developer_reviewed else ''
        lines.append(f'  {c.commit_hash}  {tag_status}  {tools}  {reviewed}')
        lines.append(f'             {c.subject[:55]}')
    lines.append(sep)

    return '\n'.join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Scan PR commits for AI attribution')
    parser.add_argument('--base-branch', default='main')
    parser.add_argument('--pr-number', default=None)
    parser.add_argument('--pr-body', default='', help='PR description text')
    parser.add_argument('--pr-body-file', default=None, help='File containing PR description')
    parser.add_argument('--output', choices=['text', 'json'], default='text')
    parser.add_argument('--fail-on-risk', choices=['critical', 'high', 'medium', 'any'],
                        default='critical')
    args = parser.parse_args()

    pr_body = args.pr_body
    if args.pr_body_file and os.path.exists(args.pr_body_file):
        with open(args.pr_body_file) as f:
            pr_body = f.read()

    report = build_report(args.base_branch, args.pr_number, pr_body)

    if args.output == 'json':
        print(json.dumps(asdict(report), indent=2))
    else:
        print(render_text(report))

    fail_ranks = {'critical': 3, 'high': 2, 'medium': 1, 'any': 0}
    risk_ranks = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    should_fail = risk_ranks.get(report.risk_level, 0) >= fail_ranks.get(args.fail_on_risk, 3)
    sys.exit(1 if should_fail else 0)


if __name__ == '__main__':
    main()
