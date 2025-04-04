import { Component, Input } from '@angular/core';
import {ListComponent} from '../components/list/list.component'
import { LogsService } from '../services/api.service';
import { Subscription } from 'rxjs';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { CommonModule } from '@angular/common';


@Component({
  selector: 'app-info-machine',
  standalone: true,
  imports: [MatTableModule, CommonModule],
  templateUrl: './info-machine.component.html',
  styleUrls: ['./info-machine.component.scss']
})
export class InfoMachineComponent {
  selectedLog: any = null;
  private selectedLogSubscription: Subscription | null = null;

  constructor(
    private listComponent: ListComponent,
    private logsService: LogsService
  ) {}
  
  ngOnInit() {
    this.selectedLogSubscription = this.logsService.selectedLog$.subscribe((log) => {
      console.log('Selected log:', log);
      this.selectedLog = log;
    });
  }

  ngOnDestroy() {
    if (this.selectedLogSubscription) {
      this.selectedLogSubscription.unsubscribe();
    }
  }
}

