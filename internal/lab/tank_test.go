package lab_test

import (
	"testing"
	"time"

	"github.com/YeandAmen/identityshield/internal/lab"
)

func TestTankConservationAndControlledManipulation(t *testing.T) {
	tank := lab.Tank{Level: 50, Pressure: 1, Inlet: 2, Outlet: 2}
	tank.Step(10)
	if tank.Level != 50 {
		t.Fatal("balanced flows changed tank volume")
	}
	tank.Inlet, tank.Outlet = 4, 1
	tank.Step(10)
	if tank.Level != 80 || tank.Pressure <= 1 {
		t.Fatal("flow manipulation did not produce a physical response")
	}
	events := lab.TankEvents(20, 10, 42, time.Now())
	if events[9].Label != "benign" || events[10].Label != "malicious" {
		t.Fatal("controlled scenario labels do not match manipulation timing")
	}
}
