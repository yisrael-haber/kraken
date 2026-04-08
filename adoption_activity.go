package main

import (
	"net"
	"sync"
	"time"
)

const defaultAdoptionActivityCapacity = 128

type AdoptedIPAddressDetails struct {
	Label            string                           `json:"label"`
	IP               string                           `json:"ip"`
	InterfaceName    string                           `json:"interfaceName"`
	MAC              string                           `json:"mac"`
	DefaultGateway   string                           `json:"defaultGateway,omitempty"`
	OverrideBindings AdoptedIPAddressOverrideBindings `json:"overrideBindings,omitempty"`
	ARPCacheEntries  []ARPCacheItem                   `json:"arpCacheEntries,omitempty"`
	ARPEvents        []ARPActivity                    `json:"arpEvents,omitempty"`
	ICMPEvents       []ICMPActivity                   `json:"icmpEvents,omitempty"`
}

type ARPCacheItem struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	UpdatedAt string `json:"updatedAt"`
}

type ARPActivity struct {
	Timestamp string `json:"timestamp"`
	Direction string `json:"direction"`
	Event     string `json:"event"`
	PeerIP    string `json:"peerIP,omitempty"`
	PeerMAC   string `json:"peerMAC,omitempty"`
	Details   string `json:"details,omitempty"`
}

type ICMPActivity struct {
	Timestamp string  `json:"timestamp"`
	Direction string  `json:"direction"`
	Event     string  `json:"event"`
	PeerIP    string  `json:"peerIP,omitempty"`
	ID        int     `json:"id,omitempty"`
	Sequence  int     `json:"sequence,omitempty"`
	RTTMillis float64 `json:"rttMillis,omitempty"`
	Status    string  `json:"status,omitempty"`
	Details   string  `json:"details,omitempty"`
}

type activityRing[T any] struct {
	items []T
	next  int
	full  bool
}

type adoptionActivityLog struct {
	mu   sync.RWMutex
	arp  activityRing[ARPActivity]
	icmp activityRing[ICMPActivity]
}

func newAdoptionActivityLog(capacity int) *adoptionActivityLog {
	if capacity <= 0 {
		capacity = defaultAdoptionActivityCapacity
	}

	return &adoptionActivityLog{
		arp:  newActivityRing[ARPActivity](capacity),
		icmp: newActivityRing[ICMPActivity](capacity),
	}
}

func newActivityRing[T any](capacity int) activityRing[T] {
	return activityRing[T]{
		items: make([]T, capacity),
	}
}

func (ring *activityRing[T]) append(item T) {
	ring.items[ring.next] = item
	ring.next = (ring.next + 1) % len(ring.items)
	if ring.next == 0 {
		ring.full = true
	}
}

func (ring *activityRing[T]) snapshotNewestFirst() []T {
	count := ring.next
	if ring.full {
		count = len(ring.items)
	}

	snapshot := make([]T, 0, count)
	for offset := 1; offset <= count; offset++ {
		index := ring.next - offset
		if index < 0 {
			index += len(ring.items)
		}
		snapshot = append(snapshot, ring.items[index])
	}

	return snapshot
}

func (log *adoptionActivityLog) recordARP(activity ARPActivity) {
	log.mu.Lock()
	log.arp.append(activity)
	log.mu.Unlock()
}

func (log *adoptionActivityLog) recordICMP(activity ICMPActivity) {
	log.mu.Lock()
	log.icmp.append(activity)
	log.mu.Unlock()
}

func (log *adoptionActivityLog) snapshot(entry adoptionEntry) AdoptedIPAddressDetails {
	log.mu.RLock()
	defer log.mu.RUnlock()

	return AdoptedIPAddressDetails{
		Label:            entry.label,
		IP:               entry.ip.String(),
		InterfaceName:    entry.iface.Name,
		MAC:              entry.mac.String(),
		DefaultGateway:   ipString(entry.defaultGateway),
		OverrideBindings: normalizeAdoptedIPAddressOverrideBindings(entry.overrideBindings),
		ARPEvents:        log.arp.snapshotNewestFirst(),
		ICMPEvents:       log.icmp.snapshotNewestFirst(),
	}
}

func (log *adoptionActivityLog) clear(scope string) error {
	log.mu.Lock()
	defer log.mu.Unlock()

	switch scope {
	case "arp":
		log.arp = newActivityRing[ARPActivity](len(log.arp.items))
	case "icmp":
		log.icmp = newActivityRing[ICMPActivity](len(log.icmp.items))
	default:
		return net.InvalidAddrError("unsupported activity scope")
	}

	return nil
}

func (entry adoptionEntry) recordARP(direction, event string, peerIP net.IP, peerMAC net.HardwareAddr, details string) {
	if entry.activity == nil {
		return
	}

	entry.activity.recordARP(ARPActivity{
		Timestamp: activityTimestamp(),
		Direction: direction,
		Event:     event,
		PeerIP:    ipString(peerIP),
		PeerMAC:   cloneHardwareAddr(peerMAC).String(),
		Details:   details,
	})
}

func (entry adoptionEntry) recordICMP(direction, event string, peerIP net.IP, id, sequence uint16, rtt time.Duration, status, details string) {
	if entry.activity == nil {
		return
	}

	activity := ICMPActivity{
		Timestamp: activityTimestamp(),
		Direction: direction,
		Event:     event,
		PeerIP:    ipString(peerIP),
		ID:        int(id),
		Sequence:  int(sequence),
		Status:    status,
		Details:   details,
	}

	if rtt > 0 {
		activity.RTTMillis = float64(rtt) / float64(time.Millisecond)
	}

	entry.activity.recordICMP(activity)
}

func activityTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
