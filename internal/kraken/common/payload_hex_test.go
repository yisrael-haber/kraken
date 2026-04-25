package common

import (
	"strings"
	"testing"
)

func TestParsePayloadHexSupportsCommonFormats(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  []byte
	}{
		{name: "spaced bytes", input: "DE AD BE EF", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "continuous hex", input: "deadbeef", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "0x prefixed bytes", input: "0xDE,0xAD,0xBE,0xEF", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "blank payload", input: "", want: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := ParsePayloadHex(testCase.input)
			if err != nil {
				t.Fatalf("parse payload hex: %v", err)
			}
			if len(got) != len(testCase.want) {
				t.Fatalf("expected %d bytes, got %d", len(testCase.want), len(got))
			}
			for index := range got {
				if got[index] != testCase.want[index] {
					t.Fatalf("expected payload %v, got %v", testCase.want, got)
				}
			}
		})
	}
}

func TestParsePayloadHexRejectsInvalidInput(t *testing.T) {
	_, err := ParsePayloadHex("XYZ")
	if err == nil || (!strings.Contains(err.Error(), "hex") && !strings.Contains(err.Error(), "byte")) {
		t.Fatalf("expected invalid payload hex error, got %v", err)
	}
}
