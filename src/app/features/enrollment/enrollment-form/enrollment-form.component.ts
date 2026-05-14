import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { PatientService } from '../../../core/services/patient.service';
import { PatientEnrollment, US_STATES, GENDER_DISPLAY } from '../../../core/models/patient.model';

type Step = 'demographics' | 'coverage' | 'consent';

@Component({
  selector: 'app-enrollment-form',
  templateUrl: './enrollment-form.component.html',
  styleUrls: ['./enrollment-form.component.scss'],
})
export class EnrollmentFormComponent implements OnInit {

  readonly steps: Step[] = ['demographics', 'coverage', 'consent'];
  readonly stepLabels: Record<Step, string> = {
    demographics: '1. Patient Demographics',
    coverage:     '2. Insurance Coverage',
    consent:      '3. Consent',
  };
  readonly genderOptions = Object.entries(GENDER_DISPLAY);
  readonly usStates = US_STATES;

  currentStep: Step = 'demographics';
  isSubmitting = false;
  submitError: string | null = null;
  enrolledRefId: string | null = null;

  form!: FormGroup;

  constructor(
    private fb: FormBuilder,
    private patientService: PatientService,
    private router: Router,
  ) {}

  ngOnInit(): void {
    this.form = this.fb.group({
      demographics: this.fb.group({
        firstName:    ['', [Validators.required, Validators.maxLength(100)]],
        lastName:     ['', [Validators.required, Validators.maxLength(100)]],
        dateOfBirth:  ['', [Validators.required, this.dobValidator]],
        genderCode:   ['U', Validators.required],
        primaryPhone: ['', [Validators.required, Validators.pattern(/^\(\d{3}\)\s\d{3}-\d{4}$/)]],
        emailAddress: ['', [Validators.required, Validators.email]],
        mailingAddress: this.fb.group({
          street1: ['', Validators.required],
          street2: [''],
          city:    ['', Validators.required],
          state:   ['', Validators.required],
          zipCode: ['', [Validators.required, Validators.pattern(/^\d{5}(-\d{4})?$/)]],
        }),
      }),
      coverage: this.fb.group({
        payerId:         ['', Validators.required],
        planName:        ['', Validators.required],
        groupNumber:     ['', Validators.required],
        effectiveDate:   ['', Validators.required],
        terminationDate: [''],
      }),
      consent: this.fb.group({
        hipaaNoticeAcknowledged:       [false, Validators.requiredTrue],
        treatmentConsentGranted:       [false, Validators.requiredTrue],
        electronicCommConsentGranted:  [false],
      }),
    });
  }

  private dobValidator(control: AbstractControl): { [key: string]: boolean } | null {
    if (!control.value) return null;
    const dob = new Date(control.value);
    const now = new Date();
    const minDob = new Date();
    minDob.setFullYear(now.getFullYear() - 130);
    if (dob > now) return { futureDate: true };
    if (dob < minDob) return { tooOld: true };
    return null;
  }

  get stepGroup(): FormGroup {
    return this.form.get(this.currentStep) as FormGroup;
  }

  get currentStepIndex(): number {
    return this.steps.indexOf(this.currentStep);
  }

  stepStatus(step: Step): 'active' | 'done' | '' {
    const idx = this.steps.indexOf(step);
    if (idx === this.currentStepIndex) return 'active';
    if (idx < this.currentStepIndex) return 'done';
    return '';
  }

  next(): void {
    this.stepGroup.markAllAsTouched();
    if (this.stepGroup.invalid) return;
    const idx = this.currentStepIndex;
    if (idx < this.steps.length - 1) {
      this.currentStep = this.steps[idx + 1];
    }
  }

  back(): void {
    const idx = this.currentStepIndex;
    if (idx > 0) {
      this.currentStep = this.steps[idx - 1];
    }
  }

  fieldError(stepKey: Step, fieldPath: string): string | null {
    const ctrl = this.form.get([stepKey, ...fieldPath.split('.')]);
    if (!ctrl || !ctrl.touched || !ctrl.errors) return null;
    if (ctrl.errors['required'])     return 'This field is required.';
    if (ctrl.errors['email'])        return 'Enter a valid email address.';
    if (ctrl.errors['pattern'])      return 'Format is invalid.';
    if (ctrl.errors['requiredTrue']) return 'This consent is required to proceed.';
    if (ctrl.errors['futureDate'])   return 'Date of birth cannot be in the future.';
    if (ctrl.errors['tooOld'])       return 'Please verify the date of birth.';
    return 'Invalid value.';
  }

  submit(): void {
    this.form.markAllAsTouched();
    if (this.form.invalid) return;

    const raw = this.form.getRawValue();
    const payload: PatientEnrollment = {
      demographics:   raw.demographics,
      primaryCoverage: raw.coverage,
      consent: {
        ...raw.consent,
        acknowledgedAt: new Date().toISOString(),
      },
      enrollmentStatus: 'PENDING',
    };

    this.isSubmitting = true;
    this.submitError = null;

    this.patientService.enroll(payload).subscribe({
      next: response => {
        this.isSubmitting = false;
        this.enrolledRefId = response.referenceId;
      },
      error: () => {
        this.isSubmitting = false;
        this.submitError = 'Enrollment submission failed. Please try again.';
      },
    });
  }

  goToList(): void {
    this.router.navigate(['/enrollment']);
  }
}
