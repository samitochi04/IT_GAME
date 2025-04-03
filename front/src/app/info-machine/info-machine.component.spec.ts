import { ComponentFixture, TestBed } from '@angular/core/testing';

import { InfoMachineComponent } from './info-machine.component';

describe('InfoMachineComponent', () => {
  let component: InfoMachineComponent;
  let fixture: ComponentFixture<InfoMachineComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [InfoMachineComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(InfoMachineComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
