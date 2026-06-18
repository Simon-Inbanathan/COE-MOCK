export interface Address {
  street1: string;
  street2?: string;
  city: string;
  state: string;
  zipCode: string;
}

export type GenderCode = 'M' | 'F' | 'O' | 'U';
export type EnrollmentStatus = 'DRAFT' | 'PENDING' | 'ACTIVE' | 'INACTIVE';

export interface PatientDemographics {
  firstName: string;
  lastName: string;
  dateOfBirth: string;        // ISO format: YYYY-MM-DD
  genderCode: GenderCode;
  primaryPhone: string;
  emailAddress: string;
  mailingAddress: Address;
}

export interface InsuranceCoverage {
  payerId: string;
  planName: string;
  groupNumber: string;
  effectiveDate: string;      // ISO format: YYYY-MM-DD
  terminationDate?: string;
}

export interface PrimaryProvider {
  providerNpiRef: string;     // internal reference to NPI — NPI itself not stored here
  providerName: string;
  facilityCode: string;
}

export interface ConsentRecord {
  hipaaNoticeAcknowledged: boolean;
  treatmentConsentGranted: boolean;
  electronicCommConsentGranted: boolean;
  acknowledgedAt?: string;    // ISO datetime
}

export interface PatientEnrollment {
  referenceId?: string;       // internal non-PHI surrogate key
  demographics: PatientDemographics;
  primaryCoverage: InsuranceCoverage;
  primaryProvider?: PrimaryProvider;
  consent: ConsentRecord;
  enrollmentStatus: EnrollmentStatus;
  enrolledAt?: string;
  lastModifiedAt?: string;
}

export interface EnrollmentResponse {
  referenceId: string;
  enrollmentStatus: EnrollmentStatus;
  enrolledAt: string;
}

export interface PatientListItem {
  referenceId: string;
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  genderCode: GenderCode;
  enrollmentStatus: EnrollmentStatus;
  primaryPhone: string;
  enrolledAt: string;
}

export interface EnrollmentListItem {
  referenceId: string;
  enrollmentStatus: EnrollmentStatus;
  payerName: string;
  enrolledAt: string;
  lastModifiedAt: string;
}

export interface PagedResponse<T> {
  items: T[];
  totalCount: number;
  page: number;
  pageSize: number;
}

export const GENDER_DISPLAY: Record<GenderCode, string> = {
  M: 'Male',
  F: 'Female',
  O: 'Other',
  U: 'Unknown / Prefer not to say',
};

export const US_STATES = [
  'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA',
  'HI','ID','IL','IN','IA','KS','KY','LA','ME','MD',
  'MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ',
  'NM','NY','NC','ND','OH','OK','OR','PA','RI','SC',
  'SD','TN','TX','UT','VT','VA','WA','WV','WI','WY',
];
