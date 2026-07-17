package script

import (
	"context"
	"strings"
	"testing"
)

func TestWindowsModuleExposesProtocolByteHelpers(t *testing.T) {
	compiled, err := CompileGeneric("windows", `
load("kraken/windows", "windows")

def main(ctx):
	sid = windows.sid.parse("S-1-5-18")
	print(sid.text)
	print(len(sid.bytes))
	print(windows.sid.parse(sid.bytes).text)
	print(windows.utf16le.decode(windows.utf16le.encode("Kraken")))

	packet = windows.tds.packet(type=windows.tds.type_prelogin, data=b"abc")
	parsed = windows.tds.parse_packet(packet)
	print(parsed.type)
	print(parsed.length)
	print(parsed.data)

	prelogin = windows.tds.parse_prelogin(windows.tds.prelogin(encryption=1, instance="MSSQL"))
	print(prelogin.encryption)
	print(prelogin.instance)

	descriptor = windows.security.parse_descriptor(b"\x01\x00\x00\x80\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00")
	print(descriptor.owner.text)
	print(windows.security.access_mask_text(0x10000000))

	client = windows.ntlm.client(user="alice", password="secret", domain="LAB")
	print(len(client.negotiate()) > 0)
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGenericWithContext(context.Background(), compiled, ExecutionContext{})
	if err != nil {
		t.Fatalf("execute generic script: %v\n%s", err, result.Stderr)
	}

	expected := strings.Join([]string{
		"S-1-5-18",
		"12",
		"S-1-5-18",
		"Kraken",
		"18",
		"11",
		`b"abc"`,
		"1",
		"MSSQL",
		"S-1-5-18",
		"GENERIC_ALL",
		"True",
		"",
	}, "\n")
	if result.Stdout != expected {
		t.Fatalf("unexpected output:\n%s", result.Stdout)
	}
}
