package common

import (
	"encoding/hex"
	"strings"
)

func ParsePayloadHex(value string) ([]byte, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil, nil
	}

	return hex.DecodeString(text)
}
