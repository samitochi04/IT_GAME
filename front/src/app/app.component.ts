import { Component, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from "./header/header.component";
import { ListComponent } from "./components/list/list.component";
import { LogsService } from './services/api.service';
import { take } from 'rxjs';
import { BehaviorSubject } from 'rxjs';
import { SuspiciousIndicatorComponent } from './suspicious-indicator/suspicious-indicator.component';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, HeaderComponent, ListComponent, SuspiciousIndicatorComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {
  constructor(
    private logsService: LogsService,
  ) {}

  ngOnInit() {
    this.logsService.updateLogs();
  }
}
