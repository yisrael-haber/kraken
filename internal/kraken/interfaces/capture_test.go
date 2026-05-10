package interfaces

import (
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestListUsesAdoptablePcapDevicesForUIOptions(t *testing.T) {
	withInterfaceByName(t, func(name string) (*net.Interface, error) {
		if name == "eth0" {
			return &net.Interface{Name: "eth0", Flags: net.FlagUp}, nil
		}
		return nil, errors.New("not found")
	})
	withFindAllDevs(t, func() ([]pcap.Interface, error) {
		return []pcap.Interface{
			{Name: "capture-only"},
			{Name: "eth0"},
		}, nil
	})

	selection, err := List()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	if len(selection.Options) != 1 {
		t.Fatalf("expected 1 option, got %d", len(selection.Options))
	}
	if got := selection.Options[0]; got.Name != "eth0" {
		t.Fatalf("expected adoptable eth0, got %+v", got)
	}
}

func TestListReturnsPcapWarning(t *testing.T) {
	withFindAllDevs(t, func() ([]pcap.Interface, error) {
		return nil, errors.New("permission denied")
	})

	selection, err := List()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	if selection.Warning == "" {
		t.Fatal("expected warning")
	}
	if len(selection.Options) != 0 {
		t.Fatalf("expected no options, got %+v", selection.Options)
	}
}

func withFindAllDevs(t *testing.T, fn func() ([]pcap.Interface, error)) {
	t.Helper()
	previous := findAllDevs
	findAllDevs = fn
	t.Cleanup(func() { findAllDevs = previous })
}

func withInterfaceByName(t *testing.T, fn func(string) (*net.Interface, error)) {
	t.Helper()
	previous := interfaceByName
	interfaceByName = fn
	t.Cleanup(func() { interfaceByName = previous })
}
