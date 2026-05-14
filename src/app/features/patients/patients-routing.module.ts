import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { PatientListComponent } from './patient-list/patient-list.component';
import { PatientDetailComponent } from './patient-detail/patient-detail.component';
import { PatientContactComponent } from './patient-contact/patient-contact.component';

const routes: Routes = [
  { path: '', component: PatientListComponent },
  { path: ':id/contact', component: PatientContactComponent },
  { path: ':id', component: PatientDetailComponent },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class PatientsRoutingModule {}
