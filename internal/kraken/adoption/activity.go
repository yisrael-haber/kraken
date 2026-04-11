package adoption

import (
	"net"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const defaultAdoptionActivityCapacity = 128

type AdoptedIPAddressDetails struct {
	Label           string                 `json:"label"`
	IP              string                 `json:"ip"`
	InterfaceName   string                 `json:"interfaceName"`
	MAC             string                 `json:"mac"`
	DefaultGateway  string                 `json:"defaultGateway,omitempty"`
	ScriptName      string                 `json:"scriptName,omitempty"`
	Recording       *PacketRecordingStatus `json:"recording,omitempty"`
	ARPCacheEntries []ARPCacheItem         `json:"arpCacheEntries,omitempty"`
	ARPEvents       []ARPActivity          `json:"arpEvents,omitempty"`
	ICMPEvents      []ICMPActivity         `json:"icmpEvents,omitempty"`
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

type compactIPv4 struct {
	value [4]byte
	valid bool
}

type compactMAC struct {
	value [6]byte
	valid bool
}

type recordedARPActivity struct {
	Timestamp time.Time
	Direction string
	Event     string
	PeerIP    compactIPv4
	PeerMAC   compactMAC
	Details   string
}

type recordedICMPActivity struct {
	Timestamp time.Time
	Direction string
	Event     string
	PeerIP    compactIPv4
	ID        uint16
	Sequence  uint16
	RTT       time.Duration
	Status    string
	Details   string
}

type activityRing[T any] struct {
	items []T
	next  int
	full  bool
}

type activityLog struct {
	mu   sync.RWMutex
	arp  activityRing[recordedARPActivity]
	icmp activityRing[recordedICMPActivity]
}

func newActivityLog(capacity int) *activityLog {
	if capacity <= 0 {
		capacity = defaultAdoptionActivityCapacity
	}

	return &activityLog{
		arp:  newActivityRing[recordedARPActivity](capacity),
		icmp: newActivityRing[recordedICMPActivity](capacity),
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

func (log *activityLog) recordARP(activity recordedARPActivity) {
	log.mu.Lock()
	log.arp.append(activity)
	log.mu.Unlock()
}

func (log *activityLog) recordICMP(activity recordedICMPActivity) {
	log.mu.Lock()
	log.icmp.append(activity)
	log.mu.Unlock()
}

func (log *activityLog) snapshot(item entry) AdoptedIPAddressDetails {
	log.mu.RLock()
	defer log.mu.RUnlock()

	return AdoptedIPAddressDetails{
		Label:          item.label,
		IP:             item.ip.String(),
		InterfaceName:  item.iface.Name,
		MAC:            item.mac.String(),
		DefaultGateway: common.IPString(item.defaultGateway),
		ScriptName:     NormalizeScriptName(item.scriptName),
		ARPEvents:      snapshotARPActivities(log.arp.snapshotNewestFirst()),
		ICMPEvents:     snapshotICMPActivities(log.icmp.snapshotNewestFirst()),
	}
}

func (log *activityLog) clear(scope string) error {
	log.mu.Lock()
	defer log.mu.Unlock()

	switch scope {
	case "arp":
		log.arp = newActivityRing[recordedARPActivity](len(log.arp.items))
	case "icmp":
		log.icmp = newActivityRing[recordedICMPActivity](len(log.icmp.items))
	default:
		return net.InvalidAddrError("unsupported activity scope")
	}

	return nil
}

func (item entry) RecordARP(direction, event string, peerIP net.IP, peerMAC net.HardwareAddr, details string) {
	if item.activity == nil {
		return
	}

	item.activity.recordARP(recordedARPActivity{
		Timestamp: time.Now().UTC(),
		Direction: direction,
		Event:     event,
		PeerIP:    compactIPv4FromIP(peerIP),
		PeerMAC:   compactMACFromHardwareAddr(peerMAC),
		Details:   details,
	})
}

func (item entry) RecordICMP(direction, event string, peerIP net.IP, id, sequence uint16, rtt time.Duration, status, details string) {
	if item.activity == nil {
		return
	}

	activity := recordedICMPActivity{
		Timestamp: time.Now().UTC(),
		Direction: direction,
		Event:     event,
		PeerIP:    compactIPv4FromIP(peerIP),
		ID:        id,
		Sequence:  sequence,
		Status:    status,
		Details:   details,
	}

	if rtt > 0 {
		activity.RTT = rtt
	}

	item.activity.recordICMP(activity)
}

func compactIPv4FromIP(ip net.IP) compactIPv4 {
	normalized := common.NormalizeIPv4(ip)
	if normalized == nil {
		return compactIPv4{}
	}

	var value compactIPv4
	copy(value.value[:], normalized)
	value.valid = true
	return value
}

func (value compactIPv4) String() string {
	if !value.valid {
		return ""
	}

	return net.IP(value.value[:]).String()
}

func compactMACFromHardwareAddr(mac net.HardwareAddr) compactMAC {
	if len(mac) != 6 {
		return compactMAC{}
	}

	var value compactMAC
	copy(value.value[:], mac)
	value.valid = true
	return value
}

func (value compactMAC) String() string {
	if !value.valid {
		return ""
	}

	return net.HardwareAddr(value.value[:]).String()
}

func snapshotARPActivities(items []recordedARPActivity) []ARPActivity {
	snapshot := make([]ARPActivity, 0, len(items))
	for _, item := range items {
		snapshot = append(snapshot, ARPActivity{
			Timestamp: item.Timestamp.Format(time.RFC3339Nano),
			Direction: item.Direction,
			Event:     item.Event,
			PeerIP:    item.PeerIP.String(),
			PeerMAC:   item.PeerMAC.String(),
			Details:   item.Details,
		})
	}

	return snapshot
}

func snapshotICMPActivities(items []recordedICMPActivity) []ICMPActivity {
	snapshot := make([]ICMPActivity, 0, len(items))
	for _, item := range items {
		activity := ICMPActivity{
			Timestamp: item.Timestamp.Format(time.RFC3339Nano),
			Direction: item.Direction,
			Event:     item.Event,
			PeerIP:    item.PeerIP.String(),
			ID:        int(item.ID),
			Sequence:  int(item.Sequence),
			Status:    item.Status,
			Details:   item.Details,
		}
		if item.RTT > 0 {
			activity.RTTMillis = float64(item.RTT) / float64(time.Millisecond)
		}
		snapshot = append(snapshot, activity)
	}

	return snapshot
}
