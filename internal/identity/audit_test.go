package identity_test

import (
	"testing"
	"time"

	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/identity"
	"github.com/YeandAmen/underdog/internal/lab"
)

func TestNestedMembershipCycleTerminates(t *testing.T) {
	snapshot := lab.Snapshot(time.Now())
	snapshot.Groups[0].Members = []string{"dl-reset"}
	if err := identity.Validate(snapshot); err != nil {
		t.Fatal(err)
	}
	paths := identity.MembershipPaths(snapshot, snapshot.Users[0])
	if got := paths["dl-engineering-admin"]; len(got) != 3 || got[0] != "maya.chen" || got[2] != "DL_Engineering_LocalAdmin" {
		t.Fatalf("unexpected nested path: %#v", got)
	}
	if len(paths) > len(snapshot.Groups)+1 {
		t.Fatal("cycle caused unbounded membership expansion")
	}
}

func hasEngineeringDrift(snapshot domain.Snapshot) bool {
	for _, f := range identity.Audit(snapshot) {
		if f.UserID == "maya.chen" && f.Resource == "ns-eng01" && f.Right == "local-admin" {
			return true
		}
	}
	return false
}

func TestCanonicalGrantPrecedence(t *testing.T) {
	t.Run("explicit deny defeats inherited allow", func(t *testing.T) {
		s := lab.Snapshot(time.Now())
		s.Grants = append(s.Grants, domain.Grant{ID: "deny-maya", Principal: "maya.chen", Resource: "ns-eng01", Right: "local-admin", Effect: "deny"})
		if hasEngineeringDrift(s) {
			t.Fatal("explicit denial was ignored")
		}
	})
	t.Run("explicit allow precedes inherited denial", func(t *testing.T) {
		s := lab.Snapshot(time.Now())
		s.Grants = append(s.Grants, domain.Grant{ID: "allow-maya", Principal: "maya.chen", Resource: "ns-eng01", Right: "local-admin", Effect: "allow"}, domain.Grant{ID: "deny-inherited", Principal: "gg-helpdesk", Resource: "ns-eng01", Right: "local-admin", Effect: "deny", Inherited: true, InheritedDepth: 1})
		if !hasEngineeringDrift(s) {
			t.Fatal("inherited denial incorrectly overrode an explicit allowance")
		}
	})
	t.Run("nearest inherited generation is evaluated first", func(t *testing.T) {
		s := lab.Snapshot(time.Now())
		s.Grants = append(s.Grants, domain.Grant{ID: "deny-distant", Principal: "gg-helpdesk", Resource: "ns-eng01", Right: "local-admin", Effect: "deny", Inherited: true, InheritedDepth: 2})
		if !hasEngineeringDrift(s) {
			t.Fatal("a more distant ancestor overrode the nearer allowance")
		}
	})
}

func TestRejectUserIDAsGroupMembership(t *testing.T) {
	s := lab.Snapshot(time.Now())
	s.Users[0].Groups = append(s.Users[0].Groups, "noah.williams")
	if err := identity.Validate(s); err == nil {
		t.Fatal("user IDs must not be accepted as group IDs")
	}
}
