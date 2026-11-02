package research_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/lab"
	"github.com/YeandAmen/underdog/internal/research"
)

func TestGroupHoldoutAndNoTestLabelLeakage(t *testing.T) {
	events := lab.Baseline(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC))
	model, err := research.Train(events, "authentication", "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, groupSet := range [][]string{model.TrainingGroups, model.ValidationGroups, model.TestGroups} {
		for _, group := range groupSet {
			if seen[group] {
				t.Fatal("a scenario run leaked across splits")
			}
			seen[group] = true
		}
	}
	testGroups := map[string]bool{}
	for _, group := range model.TestGroups {
		testGroups[group] = true
	}
	for i := range events {
		if testGroups[events[i].Source+"/"+events[i].RunID] {
			events[i].Label = "benign"
		}
	}
	changed, err := research.Train(events, "authentication", "")
	if err != nil {
		t.Fatal(err)
	}
	if model.Threshold != changed.Threshold || !reflect.DeepEqual(model.Trees, changed.Trees) {
		t.Fatal("test labels influenced fitted trees or validation threshold")
	}
}

func TestUnknownActivityCannotTrainAsNormal(t *testing.T) {
	events := lab.Baseline(time.Now())
	for i := range events {
		events[i].Label = "unknown"
	}
	if _, err := research.Train(events, "authentication", ""); err == nil {
		t.Fatal("unlabelled activity was silently treated as verified normal")
	}
}

func TestRenamedDuplicateDoesNotCreateNewSample(t *testing.T) {
	event := domain.Event{ID: "first", Timestamp: time.Now(), Kind: "auth_success", Actor: "u1", Host: "h1", RunID: "run-one", Source: "s1", Label: "benign", Data: map[string]string{"logon_type": "3"}}
	copy := event
	copy.ID, copy.RunID = "renamed", "different-run"
	samples, _, _, err := research.BuildSamples([]domain.Event{event, copy}, "authentication")
	if err != nil || len(samples) != 1 {
		t.Fatalf("renamed evidence bypassed deduplication: %d, %v", len(samples), err)
	}
}

func TestMissingMetricDenominatorsRemainUnavailable(t *testing.T) {
	metrics := research.Evaluate([]research.ScoredSample{{Score: .1, Label: "benign"}, {Score: .8, Label: "unknown"}}, .5)
	if metrics.Precision != nil || metrics.Recall != nil || metrics.AP != nil || metrics.Unknown != 1 {
		t.Fatal("missing denominators were represented as measured zero/one scores")
	}
}
