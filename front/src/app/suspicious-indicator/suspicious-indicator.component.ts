import { Component } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { LogsService } from '../services/api.service';
import { Subscription } from 'rxjs';
import { CommonModule } from '@angular/common';
import { ChangeDetectorRef } from '@angular/core';

@Component({
  selector: 'app-suspicious-indicator',
  imports: [MatButtonModule, MatIconModule, CommonModule],
  templateUrl: './suspicious-indicator.component.html',
  styleUrl: './suspicious-indicator.component.scss'
})
export class SuspiciousIndicatorComponent {
  logs: any = null;
  private subscription!: Subscription;
  
 constructor(
  private logsService: LogsService,
  private cdr: ChangeDetectorRef
) {}

 ngOnInit() {
    // Subscribe to the logs observable to get the latest logs
    this.subscription = this.logsService.logs$.subscribe((logs) => {
      this.logs = logs;
      this.cdr.detectChanges();
    });
  }
}