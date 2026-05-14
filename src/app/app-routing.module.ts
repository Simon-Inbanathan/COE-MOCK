import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

const routes: Routes = [
  {
    path: '',
    redirectTo: 'patients',
    pathMatch: 'full',
  },
  {
    path: 'patients',
    loadChildren: () =>
      import('./features/patients/patients.module').then(m => m.PatientsModule),
  },
  {
    path: 'enrollment',
    loadChildren: () =>
      import('./features/enrollment/enrollment.module').then(m => m.EnrollmentModule),
  },
  {
    path: '**',
    redirectTo: 'patients',
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
