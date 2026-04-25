package common

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

func ParsePayloadHex(value string) ([]byte, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil, nil
	}

	tokens := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ':' || r == ';'
	})
	if len(tokens) > 1 {
		payload := make([]byte, 0, len(tokens))
		for _, token := range tokens {
			normalized := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(token), "0x"))
			if normalized == "" || len(normalized) > 2 {
				return nil, fmt.Errorf("invalid byte %q", token)
			}
			if len(normalized) == 1 {
				normalized = "0" + normalized
			}

			parsed, err := strconv.ParseUint(normalized, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid byte %q", token)
			}
			payload = append(payload, byte(parsed))
		}

		return payload, nil
	}

	normalized := strings.TrimPrefix(strings.ToLower(text), "0x")
	if len(normalized)%2 != 0 {
		return nil, fmt.Errorf("hex payload must contain an even number of digits")
	}

	payload, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid hex payload: %w", err)
	}

	return payload, nil
}

func FormatPayloadHex(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	parts := make([]string, len(payload))
	for index, value := range payload {
		parts[index] = fmt.Sprintf("%02X", value)
	}

	return strings.Join(parts, " ")
}
