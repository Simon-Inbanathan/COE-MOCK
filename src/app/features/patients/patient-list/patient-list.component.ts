import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { PatientService } from '../../../core/services/patient.service';
import { PatientListItem, EnrollmentStatus, GENDER_DISPLAY } from '../../../core/models/patient.model';

@Component({
  selector: 'app-patient-list',
  templateUrl: './patient-list.component.html',
  styleUrls: ['./patient-list.component.scss'],
})
export class PatientListComponent implements OnInit {

  patients: PatientListItem[] = [];
  totalCount = 0;
  page = 1;
  pageSize = 20;
  searchTerm = '';
  isLoading = false;
  loadError: string | null = null;

  readonly genderDisplay = GENDER_DISPLAY;

  constructor(
    private patientService: PatientService,
    private router: Router,
  ) {}

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.isLoading = true;
    this.loadError = null;
    this.patientService
      .listPatients(this.page, this.pageSize, this.searchTerm || undefined)
      .subscribe({
        next: response => {
          this.patients = response.items;
          this.totalCount = response.totalCount;
          this.isLoading = false;
          console.log('Patients loaded:', response.items.map(p => `${p.firstName} ${p.lastName} DOB:${p.dateOfBirth}`));
        },
        error: () => {
          this.loadError = 'Failed to load patients. Please try again.';
          this.isLoading = false;
        },
      });
  }

  onSearch(value: string): void {
    this.searchTerm = value;
    this.page = 1;
    this.load();
  }

  get totalPages(): number {
    return Math.ceil(this.totalCount / this.pageSize);
  }

  prevPage(): void {
    if (this.page > 1) { this.page--; this.load(); }
  }

  nextPage(): void {
    if (this.page < this.totalPages) { this.page++; this.load(); }
  }

  viewPatient(referenceId: string): void {
    this.router.navigate(['/patients', referenceId]);
  }

  badgeClass(status: EnrollmentStatus): string {
    const map: Record<EnrollmentStatus, string> = {
      ACTIVE:   'badge-success',
      PENDING:  'badge-warning',
      DRAFT:    'badge-info',
      INACTIVE: 'badge-danger',
    };
    return map[status] ?? 'badge-info';
  }
}
