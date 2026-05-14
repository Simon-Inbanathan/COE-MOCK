import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { environment } from '@env/environment';
import {
  EnrollmentListItem,
  EnrollmentResponse,
  PagedResponse,
  PatientEnrollment,
} from '../models/patient.model';
import { AuditLogService } from './audit-log.service';

@Injectable({ providedIn: 'root' })
export class PatientService {

  private readonly baseUrl = `${environment.apiBaseUrl}/enrollments`;

  constructor(
    private http: HttpClient,
    private auditLog: AuditLogService,
  ) {}

  enroll(enrollment: PatientEnrollment): Observable<EnrollmentResponse> {
    return this.http.post<EnrollmentResponse>(this.baseUrl, enrollment).pipe(
      tap(response => {
        this.auditLog.log({
          eventType: 'PATIENT_ENROLL',
          resourceType: 'PatientEnrollment',
          resourceId: response.referenceId,  // surrogate ID only — never PHI
        });
      }),
    );
  }

  getEnrollment(referenceId: string): Observable<PatientEnrollment> {
    return this.http.get<PatientEnrollment>(`${this.baseUrl}/${referenceId}`).pipe(
      tap(() => {
        this.auditLog.log({
          eventType: 'PATIENT_VIEW',
          resourceType: 'PatientEnrollment',
          resourceId: referenceId,
        });
      }),
    );
  }

  listEnrollments(page = 1, pageSize = 20, status?: string): Observable<PagedResponse<EnrollmentListItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('pageSize', pageSize.toString());

    if (status) {
      params = params.set('status', status);
    }

    return this.http.get<PagedResponse<EnrollmentListItem>>(this.baseUrl, { params });
  }

  updateStatus(referenceId: string, newStatus: string): Observable<EnrollmentResponse> {
    return this.http.patch<EnrollmentResponse>(
      `${this.baseUrl}/${referenceId}/status`,
      { status: newStatus },
    ).pipe(
      tap(() => {
        this.auditLog.log({
          eventType: 'PATIENT_UPDATE',
          resourceType: 'PatientEnrollment',
          resourceId: referenceId,
          metadata: { newStatus },
        });
      }),
    );
  }
}
