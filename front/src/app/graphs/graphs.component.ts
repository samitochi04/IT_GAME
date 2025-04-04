import { Component } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { LogsService } from '../services/api.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-graphs',
  imports: [MatCardModule],
  templateUrl: './graphs.component.html',
  styleUrl: './graphs.component.scss'
})
export class GraphsComponent {
  constructor(
    private logsService: LogsService,
  ) {}
  private subscription!: Subscription;
  packetsAmount: number = 0;

  ngOnInit() {
    this.subscription = this.logsService.logs$.subscribe((logs) => {
      this.packetsAmount = logs.packets_count;
    });
  }
}
