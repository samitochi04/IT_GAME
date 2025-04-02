import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AppComponent } from '../../app.component';
import { Subscription } from 'rxjs';
import { LogsService } from '../../services/api.service';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';

@Component({
  selector: 'app-list',
  imports: [CommonModule, MatTableModule],
  templateUrl: './list.component.html',
  styleUrl: './list.component.scss'
})
export class ListComponent {
  columnsToDisplay = ['Time', 'IP Source', 'IP Destination', 'Port Source', 'Port Destination', 'Information'];
  logs: any[] = [];
  private subscription!: Subscription;

  constructor(private logsService: LogsService) {}

  ngOnInit(): void {
    // Subscribe to the logs observable to get the latest logs
    this.subscription = this.logsService.logs$.subscribe((logs) => {
      this.logs = logs;
    });
  }

  ngOnDestroy(): void {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }
}
