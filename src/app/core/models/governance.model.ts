export interface ScanFinding {
  rule_id: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  category?: string;
  package?: string;
  installed_version?: string;
  cve?: string;
  summary?: string;
}

export interface ScanSummary {
  scanner: string;
  passed: boolean;
  finding_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  findings: ScanFinding[];
}

export interface Scorecard {
  team_name: string;
  platform: string;
  stage: string;
  timestamp: string;
  build_ref: string;
  pr_number: string | null;
  overall_passed: boolean;
  baa_verified: boolean;
  scans: ScanSummary[];
  escalated_to: string[];
  block_reason: string | null;
}

export interface SecurityFinding {
  gate: string;
  severity: string;
  file: string;
  line: number;
  rule_id: string;
  message: string;
  cwe: string;
  owasp_category: string;
  detail: string;
  requires_pentest_signoff: boolean;
  remediation: string;
}

export interface SecurityAttestation {
  findings: SecurityFinding[];
  sbom_generated: boolean;
  sbom_path: string;
  iac_scanned: boolean;
  llm_surfaces_found: number;
  pentest_required: boolean;
  overall_passed: boolean;
}

export interface GateSummary {
  name: string;
  description: string;
  passed: boolean;
  critical: number;
  high: number;
  medium: number;
  low: number;
}
