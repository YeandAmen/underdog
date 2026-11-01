package datasets_test

import (
	"strings"
	"testing"

	"github.com/YeandAmen/identityshield/internal/datasets"
)

func TestPublisherHAISemicolonCSVAndRawRecordPreservation(t *testing.T) {
	result, err := datasets.Parse([]byte("time;P1_B2004;P2_24Vdc;attack;attack_P1\r\n20191029 14:00:01;1.25;24;1;1\r\n"), datasets.Options{Format: "hai-csv", Source: "hai"})
	if err != nil {
		t.Fatal(err)
	}
	event := result.Events[0]
	if event.Label != "malicious" || event.Data["P2_24Vdc"] != "24" || !strings.Contains(event.Raw, ";1.25;24;1;1") {
		t.Fatalf("publisher CSV was not normalized and preserved correctly: %#v", event)
	}
}
