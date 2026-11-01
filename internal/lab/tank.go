package lab

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
)

// Tank is a deliberately small process model, not a digital twin of a plant.
// Its 100 L vessel uses mass balance and a first-order pressure response.
type Tank struct {
	Level    float64
	Pressure float64
	Inlet    float64
	Outlet   float64
}

func (t *Tank) Step(seconds float64) {
	if seconds <= 0 {
		return
	}
	t.Level = math.Max(0, t.Level+(t.Inlet-t.Outlet)*seconds)
	targetPressure := .7 + .012*t.Level + .22*t.Inlet
	t.Pressure += (targetPressure - t.Pressure) * (1 - math.Exp(-seconds/8))
}

func TankEvents(samples, attackAfter int, seed uint64, start time.Time) []domain.Event {
	rng := rand.New(rand.NewPCG(seed, 2026))
	tank := Tank{Level: 52, Pressure: 1.5, Inlet: 1.8, Outlet: 1.8}
	events := make([]domain.Event, 0, samples)
	runID := fmt.Sprintf("tank-%d-%d", seed, start.UnixNano())
	for i := 0; i < samples; i++ {
		label := "benign"
		tank.Inlet, tank.Outlet = 1.8+rng.Float64()*.08, 1.8+rng.Float64()*.08
		if attackAfter >= 0 && i >= attackAfter {
			tank.Inlet, tank.Outlet, label = 4.8, .2, "malicious"
		}
		tank.Step(5)
		events = append(events, newEvent(runID, i, start.Add(time.Duration(i)*5*time.Second), "ics_sample", "controller", "ns-plc01", label, map[string]string{
			"schema": "northstar-tank-v1", "mode": "running", "tank_level": fmt.Sprintf("%.4f", tank.Level), "pressure": fmt.Sprintf("%.4f", tank.Pressure), "flow_rate": fmt.Sprintf("%.4f", tank.Inlet), "pump": "1", "process_model": "100 L mass balance; first-order pressure",
		}))
	}
	return events
}
