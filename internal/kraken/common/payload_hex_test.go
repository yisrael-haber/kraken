package common

import "testing"

func TestParsePayloadHexSupportsCommonFormats(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  []byte
	}{
		{name: "continuous hex", input: "deadbeef", want: []byte{0xde, 0xad, 0xbe, 0xef}},
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
	for _, input := range []string{"XYZ", "DE AD BE EF", "0xDEAD", "f"} {
		if _, err := ParsePayloadHex(input); err == nil {
			t.Fatalf("expected invalid payload hex error for %q", input)
		}
	}
}
