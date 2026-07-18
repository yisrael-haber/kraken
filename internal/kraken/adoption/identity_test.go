package adoption

import (
	"encoding/json"
	"net"
	"testing"
)

type discardPacketEndpoint struct{}

func (discardPacketEndpoint) Write([]byte) error { return nil }

func TestIdentityInitializationContract(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	identity := Identity{
		Label: "test_identity",
		IP:    net.ParseIP("192.0.2.10"),
		Interface: net.Interface{
			Name:         "eth-test",
			MTU:          1400,
			HardwareAddr: mac,
			Flags:        net.FlagUp,
		},
	}
	if err := identity.init(discardPacketEndpoint{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.close)

	payload, err := json.Marshal(&identity)
	if err != nil {
		t.Fatal(err)
	}
	var result Identity
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}

	if result.Label != identity.Label || !result.IP.Equal(identity.IP) || result.Interface.Name != identity.Interface.Name ||
		net.HardwareAddr(result.MAC).String() != mac.String() || result.SubnetPrefix != 24 || result.MTU != 1400 {
		t.Fatalf("unexpected initialized identity: %+v", result)
	}
}
