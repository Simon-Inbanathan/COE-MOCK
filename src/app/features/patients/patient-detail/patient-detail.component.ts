import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { PatientService } from '../../../core/services/patient.service';
import { PatientEnrollment, GENDER_DISPLAY } from '../../../core/models/patient.model';

@Component({
  selector: 'app-patient-detail',
  templateUrl: './patient-detail.component.html',
  styleUrls: ['./patient-detail.component.scss'],
})
export class PatientDetailComponent implements OnInit {

  patient: PatientEnrollment | null = null;
  isLoading = false;
  loadError: string | null = null;

  readonly genderDisplay = GENDER_DISPLAY;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private patientService: PatientService,
  ) {}

  ngOnInit(): void {
    const referenceId = this.route.snapshot.paramMap.get('id');
    if (referenceId) {
      this.loadPatient(referenceId);
    }
  }

  private loadPatient(referenceId: string): void {
    this.isLoading = true;
    this.loadError = null;
    this.patientService.getEnrollment(referenceId).subscribe({
      next: patient => {
        this.patient = patient;
        this.isLoading = false;
      },
      error: () => {
        this.loadError = 'Failed to load patient details. Please try again.';
        this.isLoading = false;
      },
    });
  }

  goBack(): void {
    this.router.navigate(['/patients']);
  }

  formatAddress(): string {
    if (!this.patient) return '';
    const addr = this.patient.demographics.mailingAddress;
    const line1 = addr.street1 + (addr.street2 ? ', ' + addr.street2 : '');
    return `${line1}, ${addr.city}, ${addr.state} ${addr.zipCode}`;
  }
}
