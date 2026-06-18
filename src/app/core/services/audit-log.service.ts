import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '@env/environment';
import { AuditLogEntry } from '../models/audit-log.model';

@Injectable({ providedIn: 'root' })
export class AuditLogService {

  private readonly endpoint = `${environment.apiBaseUrl}/audit-log`;

  constructor(private http: HttpClient) {}

  log(entry: AuditLogEntry): void {
    const payload = {
      ...entry,
      timestamp: new Date().toISOString(),
      // resourceId is always a non-PHI surrogate — safe to log
    };

    this.http.post(this.endpoint, payload).subscribe({
      error: () => {
        // Silent failure — audit log delivery is best-effort client-side.
        // Server-side audit log is the authoritative record.
      },
    });
  }
}
