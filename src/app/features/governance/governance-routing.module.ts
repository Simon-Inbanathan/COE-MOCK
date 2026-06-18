import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { GovernanceDashboardComponent } from './governance-dashboard/governance-dashboard.component';

const routes: Routes = [
  { path: '', component: GovernanceDashboardComponent },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class GovernanceRoutingModule {}
