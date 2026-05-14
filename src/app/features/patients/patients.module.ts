import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { PatientsRoutingModule } from './patients-routing.module';
import { PatientListComponent } from './patient-list/patient-list.component';
import { PatientDetailComponent } from './patient-detail/patient-detail.component';

@NgModule({
  declarations: [
    PatientListComponent,
    PatientDetailComponent,
  ],
  imports: [
    CommonModule,
    PatientsRoutingModule,
  ],
})
export class PatientsModule {}
