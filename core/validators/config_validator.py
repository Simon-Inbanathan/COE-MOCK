"""
Validates governance.yaml and returns a typed config object.
Raises ConfigValidationError with clear messages on invalid config.
"""

import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


SUPPORTED_PLATFORMS = {"github", "bitbucket", "azure-devops", "gitlab"}
SUPPORTED_STACKS = {"java", "python", "node", "dotnet", "go", "ruby"}
SUPPORTED_SEVERITIES = {"critical", "high", "medium", "low"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ConfigValidationError(Exception):
    pass


@dataclass
class TeamConfig:
    name: str
    platform: str
    architect: str
    tech_lead: str
    tech_stack: List[str]
    clinical_reviewers: List[str]


@dataclass
class BAAConfig:
    verified: bool
    vendor: str
    notes: str


@dataclass
class PreCommitChecks:
    phi_detection: bool = True
    secrets_scan: bool = True
    sast: bool = True


@dataclass
class PRGateChecks:
    sast: bool = True
    dependency_scan: bool = True
    hipaa_checks: bool = True
    clinical_review_required: bool = True
    post_results_as_comment: bool = True


@dataclass
class PipelineGateChecks:
    compliance_scorecard: bool = True
    block_on_open_criticals: bool = True


@dataclass
class Thresholds:
    block_on_severity: str = "critical"
    escalate_on_severity: str = "high"
    max_allowed_highs: int = 0


@dataclass
class PHIPatterns:
    custom_identifiers: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)


@dataclass
class GovernanceConfig:
    team: TeamConfig
    baa: BAAConfig
    pre_commit: PreCommitChecks
    pr_gate: PRGateChecks
    pipeline_gate: PipelineGateChecks
    thresholds: Thresholds
    phi_patterns: PHIPatterns
    clinical_keywords: List[str]


def _require(d: dict, key: str, section: str) -> any:
    if key not in d or d[key] is None:
        raise ConfigValidationError(f"Missing required field '{key}' in [{section}]")
    return d[key]


def _validate_email(value: str, field_name: str):
    if not EMAIL_RE.match(value):
        raise ConfigValidationError(f"Invalid email for '{field_name}': {value}")


def load_and_validate(config_path: str = "governance.yaml") -> GovernanceConfig:
    if not os.path.exists(config_path):
        raise ConfigValidationError(
            f"governance.yaml not found at '{config_path}'. "
            "Copy governance.yaml.template from the framework repo and fill it in."
        )

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigValidationError("governance.yaml must be a YAML mapping.")

    errors = []

    # ── team ──────────────────────────────────────────────────────────────
    team_raw = raw.get("team", {})
    team_name = team_raw.get("name", "").strip()
    if not team_name or team_name == "Your Team Name":
        errors.append("[team.name] must be set to your actual team name.")

    platform = team_raw.get("platform", "").lower()
    if platform not in SUPPORTED_PLATFORMS:
        errors.append(f"[team.platform] must be one of {sorted(SUPPORTED_PLATFORMS)}, got '{platform}'.")

    architect = team_raw.get("architect", "")
    if not architect or not EMAIL_RE.match(architect):
        errors.append(f"[team.architect] must be a valid email address, got '{architect}'.")

    tech_lead = team_raw.get("tech_lead", "")
    if not tech_lead or not EMAIL_RE.match(tech_lead):
        errors.append(f"[team.tech_lead] must be a valid email address, got '{tech_lead}'.")

    tech_stack = team_raw.get("tech_stack", [])
    if not tech_stack:
        errors.append("[team.tech_stack] must list at least one technology.")
    unknown_stacks = [s for s in tech_stack if s not in SUPPORTED_STACKS]
    if unknown_stacks:
        errors.append(f"[team.tech_stack] unknown values: {unknown_stacks}. Supported: {sorted(SUPPORTED_STACKS)}.")

    clinical_reviewers = team_raw.get("clinical_reviewers", [])

    # ── baa ───────────────────────────────────────────────────────────────
    baa_raw = raw.get("baa", {})
    baa_verified = baa_raw.get("verified", False)
    baa_vendor = baa_raw.get("vendor", "")
    if not baa_verified:
        # Warning, not a hard error — but we surface it prominently
        errors.append(
            "[baa.verified] is false. Confirm a signed BAA exists with your AI vendor "
            "before developers use AI tools with any PHI examples."
        )

    # ── thresholds ────────────────────────────────────────────────────────
    thresh_raw = raw.get("thresholds", {})
    block_sev = thresh_raw.get("block_on_severity", "critical")
    esc_sev = thresh_raw.get("escalate_on_severity", "high")
    if block_sev not in SUPPORTED_SEVERITIES:
        errors.append(f"[thresholds.block_on_severity] must be one of {sorted(SUPPORTED_SEVERITIES)}.")
    if esc_sev not in SUPPORTED_SEVERITIES:
        errors.append(f"[thresholds.escalate_on_severity] must be one of {sorted(SUPPORTED_SEVERITIES)}.")

    if errors:
        formatted = "\n".join(f"  • {e}" for e in errors)
        raise ConfigValidationError(f"governance.yaml has {len(errors)} error(s):\n{formatted}")

    # ── assemble ──────────────────────────────────────────────────────────
    checks_raw = raw.get("checks", {})
    pre_raw = checks_raw.get("pre_commit", {})
    pr_raw = checks_raw.get("pr_gate", {})
    pipe_raw = checks_raw.get("pipeline_gate", {})
    phi_raw = raw.get("phi_patterns", {})
    clinical_raw = raw.get("clinical_keywords", {})

    return GovernanceConfig(
        team=TeamConfig(
            name=team_name,
            platform=platform,
            architect=architect,
            tech_lead=tech_lead,
            tech_stack=tech_stack,
            clinical_reviewers=clinical_reviewers,
        ),
        baa=BAAConfig(
            verified=baa_verified,
            vendor=baa_vendor,
            notes=baa_raw.get("notes", ""),
        ),
        pre_commit=PreCommitChecks(
            phi_detection=pre_raw.get("phi_detection", True),
            secrets_scan=pre_raw.get("secrets_scan", True),
            sast=pre_raw.get("sast", True),
        ),
        pr_gate=PRGateChecks(
            sast=pr_raw.get("sast", True),
            dependency_scan=pr_raw.get("dependency_scan", True),
            hipaa_checks=pr_raw.get("hipaa_checks", True),
            clinical_review_required=pr_raw.get("clinical_review_required", True),
            post_results_as_comment=pr_raw.get("post_results_as_comment", True),
        ),
        pipeline_gate=PipelineGateChecks(
            compliance_scorecard=pipe_raw.get("compliance_scorecard", True),
            block_on_open_criticals=pipe_raw.get("block_on_open_criticals", True),
        ),
        thresholds=Thresholds(
            block_on_severity=block_sev,
            escalate_on_severity=esc_sev,
            max_allowed_highs=thresh_raw.get("max_allowed_highs", 0),
        ),
        phi_patterns=PHIPatterns(
            custom_identifiers=phi_raw.get("custom_identifiers", []),
            exclude_paths=phi_raw.get("exclude_paths", []),
        ),
        clinical_keywords=clinical_raw.get("trigger_terms", []),
    )


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "governance.yaml"
    try:
        cfg = load_and_validate(path)
        print(f"governance.yaml is valid. Team: {cfg.team.name} | Platform: {cfg.team.platform}")
    except ConfigValidationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)
