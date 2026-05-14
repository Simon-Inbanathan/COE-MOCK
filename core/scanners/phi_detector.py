"""
PHI Detector — scans source files for HIPAA-defined PHI patterns.

Covers all 18 HIPAA Safe Harbor identifiers that are realistically
detectable in source code: SSN, MRN, NPI, DOB, phone, email, IP,
health plan numbers, and custom field names from governance.yaml.
"""

import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import List, Optional

# ── HIPAA Safe Harbor regex patterns ──────────────────────────────────────────

BUILTIN_PATTERNS = {
    "SSN": {
        "severity": "critical",
        "description": "Social Security Number",
        "patterns": [
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b\d{9}\b(?=.*ssn|.*social)",  # 9-digit near SSN keyword
        ],
    },
    "NPI": {
        "severity": "critical",
        "description": "National Provider Identifier (10-digit)",
        "patterns": [
            r"\bnpi\s*[=:\"\']\s*[\"\'`]?\d{10}[\"\'`]?\b",
            r"\b[12]\d{9}\b(?=.*npi|.*provider)",
        ],
    },
    "MRN": {
        "severity": "critical",
        "description": "Medical Record Number",
        "patterns": [
            r"\bmrn\s*[=:\"\']\s*[\"\'`]?[A-Z0-9]{6,12}[\"\'`]?\b",
            r"\bmedical[_\-]?record[_\-]?number\s*[=:\"\']\s*[\"\'`]?[A-Z0-9]{6,12}[\"\'`]?\b",
        ],
    },
    "DOB": {
        "severity": "high",
        "description": "Date of Birth",
        "patterns": [
            r"\bdob\s*[=:\"\']\s*[\"\'`]?\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}[\"\'`]?\b",
            r"\bdate[_\-]?of[_\-]?birth\s*[=:\"\']\s*[\"\'`]?\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}[\"\'`]?\b",
            r"\bbirthdate\s*[=:\"\']\s*[\"\'`]?\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}[\"\'`]?\b",
        ],
    },
    "PHONE": {
        "severity": "high",
        "description": "US Phone Number",
        "patterns": [
            r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}\b",
        ],
    },
    "EMAIL_IN_STRING": {
        "severity": "high",
        "description": "Email address hardcoded as value (not import/config)",
        "patterns": [
            r"[=:\"\'`\s]\s*[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\s*[\"\'`]",
        ],
    },
    "IP_ADDRESS": {
        "severity": "medium",
        "description": "Hardcoded IP address (may identify a patient system)",
        "patterns": [
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        ],
    },
    "HEALTH_PLAN_NUMBER": {
        "severity": "critical",
        "description": "Health plan beneficiary / member ID pattern",
        "patterns": [
            r"\bmember[_\-]?id\s*[=:\"\']\s*[\"\'`]?[A-Z0-9]{8,15}[\"\'`]?\b",
            r"\bbeneficiary[_\-]?id\s*[=:\"\']\s*[\"\'`]?[A-Z0-9]{8,15}[\"\'`]?\b",
            r"\bsubscriber[_\-]?id\s*[=:\"\']\s*[\"\'`]?[A-Z0-9]{8,15}[\"\'`]?\b",
        ],
    },
    "ICD_CODE_WITH_CONTEXT": {
        "severity": "high",
        "description": "ICD-10 diagnosis code used as a hardcoded value",
        "patterns": [
            r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b(?=.*diagnosis|.*icd|.*condition)",
        ],
    },
    "DEA_NUMBER": {
        "severity": "critical",
        "description": "DEA registration number",
        "patterns": [
            r"\bdea\s*[=:\"\']\s*[\"\'`]?[A-Z]{2}\d{7}[\"\'`]?\b",
        ],
    },
}

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".go",
    ".rb", ".php", ".sql", ".yaml", ".yml", ".json", ".xml",
    ".properties", ".env", ".config", ".tf", ".sh", ".bash",
}

# Always skip these regardless of config
ALWAYS_EXCLUDE = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".idea", ".vscode",
}


@dataclass
class PHIFinding:
    file: str
    line_number: int
    line_content: str
    pattern_name: str
    description: str
    severity: str
    matched_text: str


def _should_exclude(path: str, exclude_globs: List[str]) -> bool:
    normalized = path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    for pattern in exclude_globs:
        # PurePosixPath.match() matches from the right, so relative patterns
        # correctly match absolute paths (e.g. "tests/fixtures/**" matches
        # "/abs/path/tests/fixtures/file.py")
        if pure.match(pattern):
            return True
    parts = normalized.split("/")
    return bool(ALWAYS_EXCLUDE.intersection(parts))


def _build_custom_patterns(custom_identifiers: List[str]) -> dict:
    if not custom_identifiers:
        return {}
    # Build patterns that match: field_name = "somevalue" or field_name: somevalue
    patterns = []
    for ident in custom_identifiers:
        escaped = re.escape(ident)
        patterns.append(
            rf"\b{escaped}\s*[=:\"\']\s*[\"\'`]?[A-Za-z0-9\-_\.@+]{{4,}}[\"\'`]?\b"
        )
    return {
        "CUSTOM_PHI_FIELD": {
            "severity": "critical",
            "description": f"Custom PHI field from governance.yaml: {custom_identifiers}",
            "patterns": patterns,
        }
    }


def _compile_all_patterns(custom_identifiers: List[str]) -> dict:
    all_patterns = {**BUILTIN_PATTERNS, **_build_custom_patterns(custom_identifiers)}
    compiled = {}
    for name, config in all_patterns.items():
        compiled[name] = {
            "severity": config["severity"],
            "description": config["description"],
            "regexes": [re.compile(p, re.IGNORECASE) for p in config["patterns"]],
        }
    return compiled


def scan_file(
    filepath: str,
    compiled_patterns: dict,
    exclude_globs: List[str],
) -> List[PHIFinding]:
    findings = []

    if _should_exclude(filepath, exclude_globs):
        return findings

    ext = os.path.splitext(filepath)[1].lower()
    if ext not in SCANNABLE_EXTENSIONS:
        return findings

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") and ext not in {".sql", ".java", ".js"}:
            continue

        for pattern_name, config in compiled_patterns.items():
            for regex in config["regexes"]:
                match = regex.search(line)
                if match:
                    findings.append(
                        PHIFinding(
                            file=filepath,
                            line_number=line_no,
                            line_content=stripped[:200],
                            pattern_name=pattern_name,
                            description=config["description"],
                            severity=config["severity"],
                            matched_text=match.group(0)[:80],
                        )
                    )
                    break  # one finding per pattern per line

    return findings


def scan_paths(
    paths: List[str],
    custom_identifiers: List[str],
    exclude_globs: List[str],
) -> List[PHIFinding]:
    compiled = _compile_all_patterns(custom_identifiers)
    all_findings: List[PHIFinding] = []

    for path in paths:
        if os.path.isfile(path):
            all_findings.extend(scan_file(path, compiled, exclude_globs))
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ALWAYS_EXCLUDE]
                for fname in files:
                    full = os.path.join(root, fname)
                    all_findings.extend(scan_file(full, compiled, exclude_globs))

    return all_findings


def severity_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 4)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Scan source files for PHI patterns")
    parser.add_argument("paths", nargs="+", help="Files or directories to scan")
    parser.add_argument("--custom-identifiers", nargs="*", default=[], help="Custom PHI field names")
    parser.add_argument("--exclude", nargs="*", default=[], help="Glob patterns to exclude")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "any"], default="critical")
    args = parser.parse_args()

    findings = scan_paths(args.paths, args.custom_identifiers, args.exclude)
    findings.sort(key=lambda f: (severity_rank(f.severity), f.file, f.line_number))

    if args.output == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("PHI scan: PASSED — no PHI patterns detected.")
        else:
            print(f"\nPHI SCAN FINDINGS ({len(findings)} total):\n{'─'*60}")
            for f in findings:
                print(f"[{f.severity.upper()}] {f.file}:{f.line_number}")
                print(f"  Type   : {f.pattern_name} — {f.description}")
                print(f"  Match  : {f.matched_text}")
                print(f"  Context: {f.line_content}")
                print()

    fail_ranks = {"critical": 0, "high": 1, "medium": 2, "any": 3}
    fail_at = fail_ranks.get(args.fail_on, 0)
    should_fail = any(severity_rank(f.severity) <= fail_at for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
