import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class LogsService {
  private apiUrl = 'http://localhost:5000/api/analyze/latest'; 

  constructor(private http: HttpClient) {}

  // Récupérer les logs depuis l'API
  getLogs(): Observable<any> {
    return this.http.get<any>(this.apiUrl);
  }
}
