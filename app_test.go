package main

import (
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

func TestStoredConfigurationIsActiveRequiresExactIdentity(t *testing.T) {
	config := storage.StoredAdoptionConfiguration{Label: "base", IP: "192.0.2.10"}
	tests := []struct {
		name   string
		active []*adoption.Identity
		want   bool
	}{
		{
			name:   "exact identity",
			active: []*adoption.Identity{{Label: "base", IP: net.ParseIP("192.0.2.10")}},
			want:   true,
		},
		{
			name:   "same address different label",
			active: []*adoption.Identity{{Label: "other", IP: net.ParseIP("192.0.2.10")}},
		},
		{
			name:   "same label different address",
			active: []*adoption.Identity{{Label: "base", IP: net.ParseIP("192.0.2.11")}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := storedConfigurationIsActive(config, test.active); got != test.want {
				t.Fatalf("storedConfigurationIsActive() = %v, want %v", got, test.want)
			}
		})
	}
}
