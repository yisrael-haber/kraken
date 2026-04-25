package interfaces

import (
	"testing"

	"github.com/google/gopacket/pcap"
)

// func TestMatchedCaptureDevicePrefersExactName(t *testing.T) {
// 	devices := map[string]pcap.Interface{
// 		"eth0": {
// 			Description: "ethernet",
// 			Addresses:   []pcap.InterfaceAddress{"192.168.56.10"},
// 		},
// 		"other": {
// 			Description: "other",
// 			Addresses:   []pcap.InterfaceAddress{"192.168.56.10"},
// 		},
// 	}

// 	deviceName, _, ok := matchedCaptureDevice("eth0", []string{"192.168.56.10"}, devices)
// 	if !ok {
// 		t.Fatal("expected exact-name capture device match")
// 	}
// 	if deviceName != "eth0" {
// 		t.Fatalf("expected exact-name device eth0, got %s", deviceName)
// 	}
// }

// func TestMatchedCaptureDeviceMatchesByAddress(t *testing.T) {
// 	devices := map[string]pcap.Interface{
// 		`\\Device\\NPF_{ABC}`: {
// 			Description: "ethernet",
// 			Addresses:   []pcap.InterfaceAddress{"10.0.0.25", "fe80::1"},
// 		},
// 	}

// 	deviceName, _, ok := matchedCaptureDevice("Ethernet", []string{"10.0.0.25"}, devices)
// 	if !ok {
// 		t.Fatal("expected address-based capture device match")
// 	}
// 	if deviceName != `\\Device\\NPF_{ABC}` {
// 		t.Fatalf("expected NPF device match, got %s", deviceName)
// 	}
// }

func TestMatchedCaptureDeviceFallsBackToDescription(t *testing.T) {
	devices := map[string]pcap.Interface{
		`\\Device\\NPF_{ABC}`: {
			Description: "Wi-Fi",
		},
	}

	deviceName, _, ok := matchedCaptureDevice("Wi-Fi", nil, devices)
	if !ok {
		t.Fatal("expected description-based capture device match")
	}
	if deviceName != `\\Device\\NPF_{ABC}` {
		t.Fatalf("expected NPF device match, got %s", deviceName)
	}
}

func TestSupportsAdoption(t *testing.T) {
	tests := []struct {
		name   string
		iface  selectionCandidate
		wantOK bool
	}{
		{
			name:   "capture only",
			iface:  selectionCandidate{captureOnly: true, captureVisible: true},
			wantOK: false,
		},
		{
			name:   "loopback",
			iface:  selectionCandidate{isLoopback: true, captureVisible: true},
			wantOK: false,
		},
		{
			name:   "not visible",
			iface:  selectionCandidate{},
			wantOK: false,
		},
		{
			name:   "adoptable",
			iface:  selectionCandidate{captureVisible: true},
			wantOK: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotOK := supportsAdoption(test.iface)
			if gotOK != test.wantOK {
				t.Fatalf("expected adoptable=%t, got %t", test.wantOK, gotOK)
			}
		})
	}
}
