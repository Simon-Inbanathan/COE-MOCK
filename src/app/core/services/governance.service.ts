import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, combineLatest, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { GateSummary, Scorecard, SecurityAttestation } from '../models/governance.model';

@Injectable({ providedIn: 'root' })
export class GovernanceService {

  constructor(private http: HttpClient) {}

  getScorecard(): Observable<Scorecard | null> {
    return this.http.get<Scorecard>('assets/governance/scorecard.json').pipe(
      catchError(() => of(null)),
    );
  }

  getSecurityAttestation(): Observable<SecurityAttestation | null> {
    return this.http.get<SecurityAttestation>('assets/governance/security-attestation.json').pipe(
      catchError(() => of(null)),
    );
  }

  getGateSummaries(): Observable<GateSummary[]> {
    return combineLatest([this.getScorecard(), this.getSecurityAttestation()]).pipe(
      map(([scorecard, security]) => {
        const gates: GateSummary[] = [];

        if (scorecard) {
          gates.push({
            name: 'PR Governance Gate',
            description: 'PHI detection · SAST (HIPAA + OWASP) · dependency CVE scan · clinical review trigger',
            passed: scorecard.overall_passed,
            critical: scorecard.scans.reduce((n, s) => n + s.critical, 0),
            high:     scorecard.scans.reduce((n, s) => n + s.high, 0),
            medium:   scorecard.scans.reduce((n, s) => n + s.medium, 0),
            low:      scorecard.scans.reduce((n, s) => n + s.low, 0),
          });
        }

        if (security) {
          const f = security.findings;
          gates.push({
            name: 'Security Attestation Gate',
            description: 'OWASP SAST · crypto primitives · XSS/injection · LLM surface · IaC · SBOM',
            passed: security.overall_passed,
            critical: f.filter(x => x.severity === 'critical').length,
            high:     f.filter(x => x.severity === 'high').length,
            medium:   f.filter(x => x.severity === 'medium').length,
            low:      f.filter(x => x.severity === 'low').length,
          });
        }

        return gates;
      }),
    );
  }
}
