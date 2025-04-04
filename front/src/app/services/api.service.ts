import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, take } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class LogsService {
  private apiUrl = 'http://localhost:5000/api/pcap/analyze';
  private logsSubject = new BehaviorSubject<any>(null);
  logs$ = this.logsSubject.asObservable();
  containerRef: any = null;

  private selectedLogSubject = new BehaviorSubject<any>(null);
  selectedLog$ = this.selectedLogSubject.asObservable();

  constructor(private http: HttpClient) {}

  updateLogs(): void {
    this.getLogs().pipe(take(1)).subscribe((newLogs) => {
      console.log('Fetched logs:', newLogs);
      this.logsSubject.next(newLogs);
    });
  }
  getLogs(): Observable<any> {
    return this.http.get<any>(this.apiUrl);
  }

  onClickedRow(log: any): void {
    this.selectedLogSubject.next([log]);
  }

  setContainerRef(containerRef: any): void {
    this.containerRef = containerRef;
  }
  getContainerRef(): any {
    return this.containerRef;
  }
}


