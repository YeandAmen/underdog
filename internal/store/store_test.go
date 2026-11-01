package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
	"github.com/YeandAmen/identityshield/internal/store"
)

func TestImportRollbackDeduplicationAndLabelProvenance(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	event := domain.Event{ID: "one", Timestamp: time.Now(), Source: "fixture", Kind: "auth_success", Actor: "user", Host: "host", Label: "unknown"}
	dataset := domain.Dataset{ID: "fixture", Name: "Fixture"}
	if _, err := db.Import(ctx, dataset, []domain.Event{event}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Import(ctx, dataset, []domain.Event{event}); err == nil {
		t.Fatal("duplicate import overwrote the original manifest")
	}
	valid, invalid := event, event
	valid.ID, invalid.ID, invalid.Label = "valid-new", "invalid-new", "unrecognised"
	if _, err := db.Import(ctx, domain.Dataset{ID: "invalid"}, []domain.Event{valid, invalid}); err == nil {
		t.Fatal("invalid import unexpectedly succeeded")
	}
	events, _ := db.Events(ctx, 100)
	if len(events) != 1 {
		t.Fatal("partially failed import left committed events")
	}
	if err := db.LabelEvent(ctx, "one", "benign", "reviewer", "Independent normal-run evidence"); err != nil {
		t.Fatal(err)
	}
	imports, _ := db.Datasets(ctx)
	if imports[0].BenignCount != 1 || imports[0].UnknownCount != 0 {
		t.Fatal("reviewed label did not update provenance counts")
	}
	events, _ = db.Events(ctx, 100)
	if events[0].Data["label_reviewer"] != "reviewer" {
		t.Fatal("review attribution was lost")
	}
}
