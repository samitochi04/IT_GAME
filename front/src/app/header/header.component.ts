import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIcon } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';

@Component({  
  selector: 'app-header',
  imports: [CommonModule, MatIcon, MatButtonModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss'
})
export class HeaderComponent {
  isDarkTheme: boolean = window.localStorage.getItem('isDarkTheme') === 'true' || false;

  toggleTheme() {
    this.isDarkTheme = !this.isDarkTheme;
    window.localStorage.setItem('isDarkTheme', JSON.stringify(this.isDarkTheme));
    this.applyTheme(this.isDarkTheme);
  }

  applyTheme(isDarkTheme: boolean) {
    document.body.classList.toggle('dark-theme', this.isDarkTheme);
  }

  ngOnInit() {
    this.applyTheme(this.isDarkTheme);
  }

}
