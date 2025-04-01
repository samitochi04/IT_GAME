import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AppComponent } from '../../app.component';
import { Subscription } from 'rxjs';
import { LogsService } from '../../services/api.service';

@Component({
  selector: 'app-list',
  imports: [CommonModule],
  templateUrl: './list.component.html',
  styleUrl: './list.component.scss'
})
export class ListComponent {
  logs: any[] = [];
  private subscription!: Subscription;
dataSource: any;

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
