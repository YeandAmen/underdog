package datasets_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/YeandAmen/identityshield/internal/datasets"
)

func TestLANLCompromiseLabelsDoNotCertifyOtherEvents(t *testing.T) {
	input := []byte("151648,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success\n151649,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOn,Fail\n")
	result, err := datasets.Parse(input, datasets.Options{Format: "lanl-auth", Source: "lanl", RedTeam: []byte("151648,U748@DOM1,C17693,C728\n")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Events[0].Label != "malicious" || result.Events[1].Label != "unknown" {
		t.Fatalf("incorrect ground-truth assignment: %#v", result.Events)
	}
	if result.Events[0].Data["relative_seconds"] != "151648" || result.Events[0].Timestamp.Year() != 1970 {
		t.Fatal("relative timestamps were misrepresented as real collection dates")
	}
}

func TestWindowsArrayInZipPreservesUnknownLabels(t *testing.T) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	file, _ := archive.Create("../../events.json")
	file.Write([]byte(`[{"EventID":4662,"TimeCreated":"2020-08-05T02:09:26Z","Computer":"MORDORDC","EventData":{"SubjectUserName":"user1","SubjectLogonId":"0x123","Properties":"{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"}}]`))
	archive.Close()
	result, err := datasets.Parse(buffer.Bytes(), datasets.Options{Format: "windows-jsonl", Source: "otrf"})
	if err != nil {
		t.Fatal(err)
	}
	event := result.Events[0]
	if event.Kind != "directory_replication" || event.Label != "unknown" || event.Actor != "user1" || event.RawSHA256 == "" {
		t.Fatalf("unexpected Windows normalization: %#v", event)
	}
}

func TestICSLabelsAreNotFeatureColumns(t *testing.T) {
	result, err := datasets.Parse([]byte("time,P1_TEMP,P1_FLOW,attack,attack_P1\n2023-05-01 00:00:01,12.2,3.1,1,1\n2023-05-01 00:00:02,12.1,3.0,0,0\n"), datasets.Options{Format: "hai-csv", Source: "hai"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Events[0].Label != "malicious" || result.Events[1].Label != "benign" {
		t.Fatal("declared ICS labels were not preserved")
	}
	for _, event := range result.Events {
		if _, exists := event.Data["attack"]; exists {
			t.Fatal("ground-truth column leaked into features")
		}
		if _, exists := event.Data["attack_P1"]; exists {
			t.Fatal("per-process ground-truth column leaked into features")
		}
	}
}

func TestMalformedTimestampIsRejected(t *testing.T) {
	_, err := datasets.Parse([]byte(`{"kind":"auth_success","timestamp":"not-a-time"}`), datasets.Options{Format: "canonical"})
	if err == nil {
		t.Fatal("malformed timestamp was accepted")
	}
}
