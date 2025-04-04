import { Component, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { LogsService } from '../../services/api.service';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { MatPaginator, MatPaginatorModule } from '@angular/material/paginator';
import { MatInputModule } from '@angular/material/input';
import { MatIcon } from '@angular/material/icon';
import { InfoMachineComponent } from '../../info-machine/info-machine.component';

export interface Logs {
  Time: string;
  IP_Source: string;
  IP_Destination: string;
  Port_Source: string;
  Port_Destination: string;
  Information: string;
}

@Component({
  selector: 'app-list',
  imports: [CommonModule, MatTableModule, MatPaginatorModule, MatInputModule, MatIcon, InfoMachineComponent],
  templateUrl: './list.component.html',
  styleUrl: './list.component.scss'
})


export class ListComponent {
  columnsToDisplay = ['Time', 'IP Source', 'IP Destination', 'Ports', 'Protocole'];
  logs: any;
  private subscription!: Subscription;
  constructor(private logsService: LogsService) {}
  dataSource: any;
  
  @ViewChild(MatPaginator) paginator!: MatPaginator;

  ngAfterViewInit() {
    this.dataSource.paginator = this.paginator;
  }

  ngOnInit(): void {
    // Subscribe to the logs observable to get the latest logs
    this.subscription = this.logsService.logs$.subscribe((logs) => {
      this.logs = logs.packets;
      this.dataSource = new MatTableDataSource<Logs>(this.logs);
      this.dataSource.paginator = this.paginator;
    });
  }

  ngOnDestroy(): void {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }

  selectedLog: any = null;
  onRowClicked(row: any) {
    this.logsService.onClickedRow(row);
  }

}
