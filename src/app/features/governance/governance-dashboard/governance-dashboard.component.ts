import { Component, OnInit } from '@angular/core';
import { Observable, combineLatest } from 'rxjs';
import { map } from 'rxjs/operators';
import { GovernanceService } from '../../../core/services/governance.service';
import { GateSummary, Scorecard, SecurityAttestation, SecurityFinding } from '../../../core/models/governance.model';

interface SecurityGateRow {
  gate: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  passed: boolean;
}

interface DashboardViewModel {
  scorecard: Scorecard | null;
  security: SecurityAttestation | null;
  gates: GateSummary[];
  securityGates: SecurityGateRow[];
  allFindings: SecurityFinding[];
}

@Component({
  selector: 'app-governance-dashboard',
  templateUrl: './governance-dashboard.component.html',
  styleUrls: ['./governance-dashboard.component.scss'],
})
export class GovernanceDashboardComponent implements OnInit {

  vm$!: Observable<DashboardViewModel>;
  expandedFindingIndex: number | null = null;

  constructor(private governanceService: GovernanceService) {}

  ngOnInit(): void {
    this.vm$ = combineLatest([
      this.governanceService.getScorecard(),
      this.governanceService.getSecurityAttestation(),
      this.governanceService.getGateSummaries(),
    ]).pipe(
      map(([scorecard, security, gates]) => ({
        scorecard,
        security,
        gates,
        securityGates: this.buildSecurityGates(security),
        allFindings: security?.findings ?? [],
      })),
    );
  }

  private buildSecurityGates(security: SecurityAttestation | null): SecurityGateRow[] {
    if (!security) return [];

    const gateMap = new Map<string, SecurityGateRow>();
    for (const f of security.findings) {
      if (!gateMap.has(f.gate)) {
        gateMap.set(f.gate, { gate: f.gate, critical: 0, high: 0, medium: 0, low: 0, passed: true });
      }
      const row = gateMap.get(f.gate)!;
      const sev = f.severity as 'critical' | 'high' | 'medium' | 'low';
      row[sev]++;
      if (sev === 'critical' || sev === 'high') row.passed = false;
    }

    const ALL_GATES = ['owasp_sast', 'crypto', 'xss_injection', 'llm_surface', 'iac', 'sbom', 'pentest'];
    const result: SecurityGateRow[] = [];
    for (const g of ALL_GATES) {
      result.push(gateMap.get(g) ?? { gate: g, critical: 0, high: 0, medium: 0, low: 0, passed: true });
    }
    return result;
  }

  gateLabel(gate: string): string {
    const labels: Record<string, string> = {
      owasp_sast:    'OWASP SAST',
      crypto:        'Crypto Primitives',
      xss_injection: 'XSS / Injection',
      llm_surface:   'LLM Surface',
      iac:           'IaC Security',
      sbom:          'SBOM',
      pentest:       'Pen-test Sign-off',
    };
    return labels[gate] ?? gate;
  }

  scannerLabel(scanner: string): string {
    const labels: Record<string, string> = {
      phi_detector:    'PHI Detector',
      sast:            'SAST (HIPAA + OWASP)',
      dependency_scan: 'Dependency CVE Scan',
    };
    return labels[scanner] ?? scanner;
  }

  severityClass(sev: string): string {
    const map: Record<string, string> = {
      critical: 'sev-critical',
      high:     'sev-high',
      medium:   'sev-medium',
      low:      'sev-low',
    };
    return map[sev] ?? 'sev-low';
  }

  toggleFinding(i: number): void {
    this.expandedFindingIndex = this.expandedFindingIndex === i ? null : i;
  }

  shortPath(file: string): string {
    const parts = file.replace(/\\/g, '/').split('/');
    return parts.length > 3 ? '…/' + parts.slice(-3).join('/') : file;
  }
}
