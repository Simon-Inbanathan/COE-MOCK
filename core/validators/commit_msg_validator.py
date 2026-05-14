"""
Commit Message AI Attribution Validator

Enforced as a commit-msg git hook. Every commit must declare which AI tools
were used (or explicitly state none). This creates a per-commit audit trail
of AI involvement without relying on tools to self-report.

Required format (tag anywhere in the commit message):
  [ai:claude]                   → Claude was used
  [ai:copilot,windsurf]         → multiple tools used
  [ai:none]                     → no AI tools used for this commit
  [ai:cursor,claude,reviewed]   → AI used, developer confirmed review

Usage (called automatically by pre-commit commit-msg hook):
  python core/validators/commit_msg_validator.py .git/COMMIT_EDITMSG
"""

import re
import sys

VALID_TOOLS = {
    "claude",
    "copilot",
    "cursor",
    "windsurf",
    "chatgpt",
    "gemini",
    "codeium",
    "tabnine",
    "other",
    "none",
    "reviewed",   # not a tool — signals human review of AI output
}

AI_TAG_PATTERN = re.compile(r'\[ai:([\w,\s]+)\]', re.IGNORECASE)

HELP_TEXT = """
─────────────────────────────────────────────────────────────
  COMMIT BLOCKED: Missing AI attribution tag
─────────────────────────────────────────────────────────────
  Every commit must declare whether AI tools were used.
  Add ONE of these tags anywhere in your commit message:

    [ai:none]                  ← no AI tool was used
    [ai:claude]                ← Claude Code was used
    [ai:copilot]               ← GitHub Copilot was used
    [ai:cursor]                ← Cursor was used
    [ai:windsurf]              ← Windsurf was used
    [ai:claude,windsurf]       ← multiple tools
    [ai:claude,reviewed]       ← AI used + you reviewed the output

  Example commit messages:
    feat: add enrollment form [ai:claude,reviewed]
    fix: correct DOB validation [ai:none]
    refactor: split patient service [ai:cursor]

  Valid tool names: claude, copilot, cursor, windsurf,
                   chatgpt, gemini, codeium, tabnine, other, none
─────────────────────────────────────────────────────────────
"""


def validate(commit_msg: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    # Skip merge commits, revert commits, and CI-generated commits
    first_line = commit_msg.strip().split('\n')[0].lower()
    skip_prefixes = ('merge ', 'revert ', 'chore(release)', 'wip:')
    if any(first_line.startswith(p) for p in skip_prefixes):
        return True, ""

    match = AI_TAG_PATTERN.search(commit_msg)
    if not match:
        return False, HELP_TEXT

    raw_values = [v.strip().lower() for v in match.group(1).split(',') if v.strip()]
    unknown = set(raw_values) - VALID_TOOLS
    if unknown:
        return False, (
            f"\n  COMMIT BLOCKED: Unknown AI tool(s) in tag: {sorted(unknown)}\n"
            f"  Valid values: {sorted(VALID_TOOLS)}\n"
        )

    return True, ""


def main():
    if len(sys.argv) < 2:
        print("Usage: commit_msg_validator.py <path-to-commit-msg-file>", file=sys.stderr)
        sys.exit(1)

    try:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            msg = f.read()
    except OSError as e:
        print(f"ERROR: could not read commit message file: {e}", file=sys.stderr)
        sys.exit(1)

    is_valid, error = validate(msg)
    if not is_valid:
        print(error, file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
