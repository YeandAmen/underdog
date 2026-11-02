package datasets_test

import (
	"testing"

	"github.com/YeandAmen/underdog/internal/datasets"
)

func TestOTRFUsesEventHostAndEventClockInsteadOfCollectorHostAndReceiveClock(t *testing.T) {
	result, err := datasets.Parse([]byte(`{"EventID":10,"@timestamp":"2020-08-05T04:00:00Z","UtcTime":"2020-08-05T02:00:00Z","Hostname":"WORKSTATION5.theshire.local","host":"wec.internal.cloudapp.net","AccountName":"operator","TargetImage":"C:\\Windows\\System32\\lsass.exe","SourceImage":"C:\\Windows\\System32\\rundll32.exe","CallTrace":"C:\\Windows\\System32\\comsvcs.dll"}`), datasets.Options{Format: "windows-jsonl", Source: "otrf"})
	if err != nil {
		t.Fatal(err)
	}
	event := result.Events[0]
	if event.Host != "WORKSTATION5.theshire.local" || event.Timestamp.Hour() != 2 || event.Kind != "process_access" || event.Actor != "operator" {
		t.Fatalf("event origin was confused with collection metadata: %#v", event)
	}
}
