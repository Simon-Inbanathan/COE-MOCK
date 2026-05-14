export type AuditEventType =
  | 'PATIENT_ENROLL'
  | 'PATIENT_VIEW'
  | 'PATIENT_UPDATE'
  | 'PATIENT_DEACTIVATE'
  | 'CONSENT_RECORD'
  | 'COVERAGE_UPDATE';

export interface AuditLogEntry {
  eventType: AuditEventType;
  resourceType: string;
  resourceId: string;         // always a non-PHI surrogate reference ID
  actorId?: string;
  metadata?: Record<string, string | number | boolean>;
}
