import { Component, OnInit, ViewChild, ViewContainerRef } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from "./header/header.component";
import { ListComponent } from "./components/list/list.component";
import { LogsService } from './services/api.service';
import { take } from 'rxjs';
import { SuspiciousIndicatorComponent } from './suspicious-indicator/suspicious-indicator.component';
import { SidePanelComponent } from './side-panel/side-panel.component';
import { InfoMachineComponent } from "./info-machine/info-machine.component";
import { GraphsComponent } from './graphs/graphs.component';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, HeaderComponent, ListComponent, SuspiciousIndicatorComponent, SidePanelComponent, InfoMachineComponent, GraphsComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {
  @ViewChild('appContentContainer', { read: ViewContainerRef, static: true }) appContentContainer!: ViewContainerRef;

  constructor(
    private logsService: LogsService,
  ) {}
  currentTheme = window.localStorage.getItem('isDarkTheme') || false;

  getContainerRef() {
    return this.appContentContainer;
  }

  ngOnInit() {
    this.logsService.updateLogs();
    // Set the container ref in the logService
    this.logsService.setContainerRef(this.appContentContainer);
  }
}
