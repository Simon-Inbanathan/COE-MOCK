import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

import { EnrollmentRoutingModule } from './enrollment-routing.module';
import { EnrollmentFormComponent } from './enrollment-form/enrollment-form.component';
import { EnrollmentListComponent } from './enrollment-list/enrollment-list.component';

@NgModule({
  declarations: [
    EnrollmentFormComponent,
    EnrollmentListComponent,
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    EnrollmentRoutingModule,
  ],
})
export class EnrollmentModule {}
