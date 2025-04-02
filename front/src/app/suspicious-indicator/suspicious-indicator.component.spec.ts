import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SuspiciousIndicatorComponent } from './suspicious-indicator.component';

describe('SuspiciousIndicatorComponent', () => {
  let component: SuspiciousIndicatorComponent;
  let fixture: ComponentFixture<SuspiciousIndicatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SuspiciousIndicatorComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SuspiciousIndicatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
