import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { PatientService } from '../../../core/services/patient.service';
import { EnrollmentListItem, EnrollmentStatus } from '../../../core/models/patient.model';

@Component({
  selector: 'app-enrollment-list',
  templateUrl: './enrollment-list.component.html',
  styleUrls: ['./enrollment-list.component.scss'],
})
export class EnrollmentListComponent implements OnInit {

  enrollments: EnrollmentListItem[] = [];
  totalCount = 0;
  page = 1;
  pageSize = 20;
  statusFilter = '';
  isLoading = false;
  loadError: string | null = null;

  readonly statusOptions: { label: string; value: string }[] = [
    { label: 'All Statuses', value: '' },
    { label: 'Active',       value: 'ACTIVE' },
    { label: 'Pending',      value: 'PENDING' },
    { label: 'Draft',        value: 'DRAFT' },
    { label: 'Inactive',     value: 'INACTIVE' },
  ];

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
      .listEnrollments(this.page, this.pageSize, this.statusFilter || undefined)
      .subscribe({
        next: response => {
          this.enrollments = response.items;
          this.totalCount  = response.totalCount;
          this.isLoading   = false;
        },
        error: () => {
          this.loadError = 'Failed to load enrollments. Please try again.';
          this.isLoading = false;
        },
      });
  }

  onStatusChange(value: string): void {
    this.statusFilter = value;
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

  viewEnrollment(referenceId: string): void {
    this.router.navigate(['/enrollment', referenceId]);
  }

  newEnrollment(): void {
    this.router.navigate(['/enrollment', 'new']);
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
