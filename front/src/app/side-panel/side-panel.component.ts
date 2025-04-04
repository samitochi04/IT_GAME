import { Component, ViewChild, ViewContainerRef, ComponentFactoryResolver } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { ListComponent } from '../components/list/list.component';
import { GraphsComponent } from '../graphs/graphs.component';
import { AppComponent } from '../app.component';
import { LogsService } from '../services/api.service';

@Component({
  selector: 'app-side-panel',
  imports: [CommonModule, MatIconModule, MatButtonModule],
  templateUrl: './side-panel.component.html',
  styleUrl: './side-panel.component.scss'
})
export class SidePanelComponent {

  constructor(
    private componentFactoryResolver: ComponentFactoryResolver,
    private logsService: LogsService,
  ) {}
  appContentContainer: any = null;

  ngOnInit() {
    this.appContentContainer = this.logsService.getContainerRef();
  }

  showHome() {
    this.appContentContainer.clear(); 
    const factory = this.componentFactoryResolver.resolveComponentFactory(ListComponent);
    this.appContentContainer.createComponent(factory); // Dynamically inject ListComponent
  }

  showGraphs() {
    this.appContentContainer.clear();
    const factory = this.componentFactoryResolver.resolveComponentFactory(GraphsComponent);
    this.appContentContainer.createComponent(factory); // Dynamically inject GraphsComponent
  }
}
