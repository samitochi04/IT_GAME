import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, take } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class LogsService {
  private apiUrl = 'http://localhost:5000/api/analyze/latest';
  private logsSubject = new BehaviorSubject<any[]>([]);
  logs$ = this.logsSubject.asObservable();

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
}


