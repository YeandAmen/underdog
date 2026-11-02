package config_test

import (
	"testing"

	"github.com/YeandAmen/underdog/internal/config"
)

func TestPublicAccessMustBeExplicitForAnUnauthenticatedNetworkListener(t *testing.T) {
	for _, test := range []struct {
		name   string
		public string
		token  string
		valid  bool
	}{
		{"private-without-token", "false", "", false},
		{"private-with-token", "false", "test-owner-token", true},
		{"explicit-public", "true", "", true},
		{"invalid-public-setting", "sometimes", "test-owner-token", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("IDENTITYSHIELD_ADDR", "0.0.0.0:8787")
			t.Setenv("IDENTITYSHIELD_ACCESS_TOKEN", test.token)
			t.Setenv("IDENTITYSHIELD_PUBLIC_ACCESS", test.public)
			t.Setenv("IDENTITYSHIELD_DEMO", "false")
			t.Setenv("IDENTITYSHIELD_AI_PROVIDER", "local")
			t.Setenv("IDENTITYSHIELD_AI_BASE_URL", "https://agentrouter.org/v1")
			t.Setenv("DATABASE_URL", "")
			t.Setenv("VERCEL", "")
			_, err := config.Load()
			if (err == nil) != test.valid {
				t.Fatalf("public access validation: %v", err)
			}
		})
	}
}
