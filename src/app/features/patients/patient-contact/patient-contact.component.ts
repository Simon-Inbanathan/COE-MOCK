import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { PatientService } from '../../../core/services/patient.service';
import { PatientEnrollment } from '../../../core/models/patient.model';

@Component({
  selector: 'app-patient-contact',
  templateUrl: './patient-contact.component.html',
  styleUrls: ['./patient-contact.component.scss'],
})
export class PatientContactComponent implements OnInit {

  patient: PatientEnrollment | null = null;
  isLoading = false;
  loadError: string | null = null;

  private referenceId: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private patientService: PatientService,
  ) {}

  ngOnInit(): void {
    this.referenceId = this.route.snapshot.paramMap.get('id');
    if (this.referenceId) {
      this.loadPatient(this.referenceId);
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
        this.loadError = 'Unable to load contact information. Please try again.';
        this.isLoading = false;
      },
    });
  }

  get formattedAddress(): string {
    if (!this.patient) return '';
    const addr = this.patient.demographics.mailingAddress;
    const line2 = addr.street2 ? `, ${addr.street2}` : '';
    return `${addr.street1}${line2}, ${addr.city}, ${addr.state} ${addr.zipCode}`;
  }

  goBack(): void {
    this.router.navigate(['/patients', this.referenceId]);
  }
}
