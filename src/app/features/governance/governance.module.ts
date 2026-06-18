import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { GovernanceRoutingModule } from './governance-routing.module';
import { GovernanceDashboardComponent } from './governance-dashboard/governance-dashboard.component';

@NgModule({
  declarations: [GovernanceDashboardComponent],
  imports: [CommonModule, GovernanceRoutingModule],
})
export class GovernanceModule {}
