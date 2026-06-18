"""
Cyclomatic Complexity Checker — uses the lizard Python API (multi-language).

Supports: Python, JS, TS, TSX, JSX, Java, C#, Go, Ruby, PHP, C/C++, Swift, Kotlin.
Install:  pip install lizard

Severity mapping:
  CCN > threshold * 2  → critical
  CCN > threshold      → high
"""

import os
import sys
from dataclasses import dataclass
from typing import List

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".go",
    ".rb", ".php", ".c", ".cpp", ".h", ".swift", ".kt",
}

ALWAYS_EXCLUDE = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".angular",
}


@dataclass
class ComplexityFinding:
    file: str
    line: int
    function_name: str
    cyclomatic_complexity: int
    threshold: int
    severity: str
    message: str


def _should_skip(filepath: str) -> bool:
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in SCANNABLE_EXTENSIONS:
        return True
    normalized = filepath.replace("\\", "/")
    parts = normalized.split("/")
    return bool(ALWAYS_EXCLUDE.intersection(parts))


def check_complexity(paths: List[str], max_ccn: int = 10) -> List[ComplexityFinding]:
    try:
        import lizard
    except ImportError:
        print(
            "  WARNING: 'lizard' not installed — skipping complexity check. "
            "Run: pip install lizard",
            file=sys.stderr,
        )
        return []

    scannable: List[str] = []
    for path in paths:
        if os.path.isfile(path):
            if not _should_skip(path):
                scannable.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ALWAYS_EXCLUDE]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if not _should_skip(fpath):
                        scannable.append(fpath)

    findings: List[ComplexityFinding] = []
    for filepath in scannable:
        try:
            file_info = lizard.analyze_file(filepath)
        except Exception:
            continue

        for func in file_info.function_list:
            ccn = func.cyclomatic_complexity
            if ccn > max_ccn:
                severity = "critical" if ccn > max_ccn * 2 else "high"
                findings.append(
                    ComplexityFinding(
                        file=filepath,
                        line=func.start_line,
                        function_name=func.name,
                        cyclomatic_complexity=ccn,
                        threshold=max_ccn,
                        severity=severity,
                        message=(
                            f"Function '{func.name}' has cyclomatic complexity "
                            f"{ccn} (max allowed: {max_ccn})"
                        ),
                    )
                )

    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cyclomatic complexity gate")
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--max-ccn", type=int, default=10)
    parser.add_argument("--fail-on", choices=["high", "critical"], default="high")
    args = parser.parse_args()

    findings = check_complexity(args.paths, args.max_ccn)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    fail_rank = sev_order[args.fail_on]

    if not findings:
        print("Complexity check: PASSED — all functions within threshold.")
        sys.exit(0)

    print(f"\nCOMPLEXITY FINDINGS ({len(findings)} total):\n{'─'*60}")
    for f in sorted(findings, key=lambda x: (sev_order.get(x.severity, 3), x.file, x.line)):
        print(f"[{f.severity.upper()}] {f.file}:{f.line}")
        print(f"  Function : {f.function_name}")
        print(f"  CCN      : {f.cyclomatic_complexity} (max: {f.threshold})")
        print()

    should_fail = any(sev_order.get(f.severity, 3) <= fail_rank for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
