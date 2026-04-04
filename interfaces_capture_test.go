package main

import "testing"

func TestMatchedCaptureDevicePrefersExactName(t *testing.T) {
	devices := map[string]captureDevice{
		"eth0": {
			Description: "ethernet",
			Addresses: []InterfaceAddress{
				{IP: "192.168.56.10"},
			},
		},
		"other": {
			Description: "other",
			Addresses: []InterfaceAddress{
				{IP: "192.168.56.10"},
			},
		},
	}

	deviceName, _, ok := matchedCaptureDevice("eth0", []InterfaceAddress{{IP: "192.168.56.10"}}, devices)
	if !ok {
		t.Fatal("expected exact-name capture device match")
	}
	if deviceName != "eth0" {
		t.Fatalf("expected exact-name device eth0, got %s", deviceName)
	}
}

func TestMatchedCaptureDeviceMatchesByAddress(t *testing.T) {
	devices := map[string]captureDevice{
		`\\Device\\NPF_{ABC}`: {
			Description: "ethernet",
			Addresses: []InterfaceAddress{
				{IP: "10.0.0.25"},
				{IP: "fe80::1"},
			},
		},
	}

	deviceName, _, ok := matchedCaptureDevice("Ethernet", []InterfaceAddress{{IP: "10.0.0.25"}}, devices)
	if !ok {
		t.Fatal("expected address-based capture device match")
	}
	if deviceName != `\\Device\\NPF_{ABC}` {
		t.Fatalf("expected NPF device match, got %s", deviceName)
	}
}

func TestMatchedCaptureDeviceFallsBackToDescription(t *testing.T) {
	devices := map[string]captureDevice{
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

func TestAdoptionSupport(t *testing.T) {
	tests := []struct {
		name   string
		iface  NetworkInterface
		wantOK bool
		want   string
	}{
		{
			name:   "capture only",
			iface:  NetworkInterface{CaptureOnly: true, CaptureVisible: true},
			want:   "capture-only device",
			wantOK: false,
		},
		{
			name:   "loopback",
			iface:  NetworkInterface{IsLoopback: true, CaptureVisible: true},
			want:   "loopback is not supported",
			wantOK: false,
		},
		{
			name:   "not visible",
			iface:  NetworkInterface{},
			want:   "no pcap device matched",
			wantOK: false,
		},
		{
			name:   "adoptable",
			iface:  NetworkInterface{CaptureVisible: true},
			wantOK: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotOK, got := adoptionSupport(test.iface)
			if gotOK != test.wantOK {
				t.Fatalf("expected adoptable=%t, got %t", test.wantOK, gotOK)
			}
			if got != test.want {
				t.Fatalf("expected issue %q, got %q", test.want, got)
			}
		})
	}
}
