package script

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

type httpHeaderField struct {
	name  string
	value string
}

func buildHTTPModule() (starlark.Value, error) {
	module := &starlarkstruct.Module{
		Name: "kraken/http",
		Members: starlark.StringDict{
			"parse": starlark.NewBuiltin("http.parse", httpParse),
			"build": starlark.NewBuiltin("http.build", httpBuild),
		},
	}
	return module, nil
}

func httpParse(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &value); err != nil {
		return nil, err
	}

	payload, err := byteSliceFromValue(value)
	if err != nil {
		return nil, fmt.Errorf("kraken/http.parse: %w", err)
	}
	return parseHTTPMessage(payload)
}

func httpBuild(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &value); err != nil {
		return nil, err
	}

	payload, err := buildHTTPMessage(value)
	if err != nil {
		return nil, err
	}
	return newOwnedByteBuffer(payload), nil
}

func parseHTTPMessage(payload []byte) (starlark.Value, error) {
	head, body := splitHTTPPayload(payload)
	lines := splitHTTPHeadLines(head)
	if len(lines) == 0 {
		return nil, fmt.Errorf("kraken/http.parse: HTTP start line is required")
	}

	headers, err := parseHTTPHeaderLines(lines[1:])
	if err != nil {
		return nil, err
	}

	fields := starlark.StringDict{
		"kind":       starlark.None,
		"version":    starlark.None,
		"method":     starlark.None,
		"target":     starlark.None,
		"statusCode": starlark.None,
		"reason":     starlark.None,
		"headers":    starlark.NewList(headers),
		"body":       newOwnedByteBuffer(append([]byte(nil), body...)),
	}

	startLine := lines[0]
	if strings.HasPrefix(startLine, "HTTP/") {
		version, statusCode, reason, err := parseHTTPResponseLine(startLine)
		if err != nil {
			return nil, err
		}
		fields["kind"] = starlark.String("response")
		fields["version"] = starlark.String(version)
		fields["statusCode"] = starlark.MakeInt(statusCode)
		fields["reason"] = starlark.String(reason)
	} else {
		method, target, version, err := parseHTTPRequestLine(startLine)
		if err != nil {
			return nil, err
		}
		fields["kind"] = starlark.String("request")
		fields["version"] = starlark.String(version)
		fields["method"] = starlark.String(method)
		fields["target"] = starlark.String(target)
	}

	return newScriptObject("http.message", true, fields), nil
}

func splitHTTPPayload(payload []byte) ([]byte, []byte) {
	if index := bytes.Index(payload, []byte("\r\n\r\n")); index >= 0 {
		return payload[:index], payload[index+4:]
	}
	if index := bytes.Index(payload, []byte("\n\n")); index >= 0 {
		return payload[:index], payload[index+2:]
	}
	return payload, nil
}

func splitHTTPHeadLines(head []byte) []string {
	normalized := strings.ReplaceAll(string(head), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	rawLines := strings.Split(normalized, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func parseHTTPRequestLine(line string) (string, string, string, error) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("kraken/http.parse: invalid HTTP request line %q", line)
	}
	return parts[0], parts[1], parts[2], nil
}

func parseHTTPResponseLine(line string) (string, int, string, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "", 0, "", fmt.Errorf("kraken/http.parse: invalid HTTP response line %q", line)
	}
	statusCode, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", 0, "", fmt.Errorf("kraken/http.parse: invalid HTTP status code %q", parts[1])
	}
	reason := ""
	if len(parts) == 3 {
		reason = parts[2]
	}
	return parts[0], statusCode, reason, nil
}

func parseHTTPHeaderLines(lines []string) ([]starlark.Value, error) {
	headers := make([]starlark.Value, 0, len(lines))
	for _, line := range lines {
		index := strings.IndexByte(line, ':')
		if index <= 0 {
			return nil, fmt.Errorf("kraken/http.parse: invalid header line %q", line)
		}
		headers = append(headers, newScriptObject("http.header", true, starlark.StringDict{
			"name":  starlark.String(strings.TrimSpace(line[:index])),
			"value": starlark.String(strings.TrimSpace(line[index+1:])),
		}))
	}
	return headers, nil
}

func buildHTTPMessage(value starlark.Value) ([]byte, error) {
	kindValue, err := attrOrNone(value, "kind")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	kind := strings.ToLower(strings.TrimSpace(starlarkStringValue(kindValue)))

	versionValue, err := attrOrNone(value, "version")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	version := starlarkStringValue(versionValue)
	if version == "" {
		version = "HTTP/1.1"
	}

	headersValue, err := attrOrNone(value, "headers")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	headers, err := httpHeadersFromValue(headersValue)
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}

	bodyValue, err := attrOrNone(value, "body")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	body, err := parseOptionalBytes(bodyValue)
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: body: %w", err)
	}

	methodValue, err := attrOrNone(value, "method")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	targetValue, err := attrOrNone(value, "target")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	statusCodeValue, err := attrOrNone(value, "statusCode")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}
	reasonValue, err := attrOrNone(value, "reason")
	if err != nil {
		return nil, fmt.Errorf("kraken/http.build: %w", err)
	}

	if kind == "" {
		if starlarkStringValue(methodValue) != "" || starlarkStringValue(targetValue) != "" {
			kind = "request"
		} else {
			kind = "response"
		}
	}

	var builder bytes.Buffer
	switch kind {
	case "request":
		method := starlarkStringValue(methodValue)
		target := starlarkStringValue(targetValue)
		if method == "" || target == "" {
			return nil, fmt.Errorf("kraken/http.build: request method and target are required")
		}
		builder.WriteString(method)
		builder.WriteByte(' ')
		builder.WriteString(target)
		builder.WriteByte(' ')
		builder.WriteString(version)
	case "response":
		statusCode, err := integerValue(statusCodeValue)
		if err != nil || statusCode < 0 || statusCode > 999 {
			return nil, fmt.Errorf("kraken/http.build: response statusCode must be between 0 and 999")
		}
		builder.WriteString(version)
		builder.WriteByte(' ')
		builder.WriteString(strconv.FormatInt(statusCode, 10))
		reason := starlarkStringValue(reasonValue)
		if reason != "" {
			builder.WriteByte(' ')
			builder.WriteString(reason)
		}
	default:
		return nil, fmt.Errorf("kraken/http.build: unsupported kind %q", kind)
	}

	builder.WriteString("\r\n")
	for _, header := range headers {
		builder.WriteString(header.name)
		builder.WriteString(": ")
		builder.WriteString(header.value)
		builder.WriteString("\r\n")
	}
	builder.WriteString("\r\n")
	builder.Write(body)
	return builder.Bytes(), nil
}

func httpHeadersFromValue(value starlark.Value) ([]httpHeaderField, error) {
	if isNone(value) {
		return nil, nil
	}

	if dict, ok := value.(*starlark.Dict); ok {
		items := dict.Items()
		headers := make([]httpHeaderField, 0, len(items))
		for _, item := range items {
			name := strings.TrimSpace(starlarkStringValue(item[0]))
			if name == "" {
				return nil, fmt.Errorf("headers must use non-empty names")
			}
			headers = append(headers, httpHeaderField{
				name:  name,
				value: starlarkStringValue(item[1]),
			})
		}
		return headers, nil
	}

	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("headers must be a dict or iterable")
	}

	headers := make([]httpHeaderField, 0, max(0, starlark.Len(value)))
	iterator := iterable.Iterate()
	defer iterator.Done()

	var item starlark.Value
	for iterator.Next(&item) {
		header, err := httpHeaderFromValue(item)
		if err != nil {
			return nil, err
		}
		headers = append(headers, header)
	}

	return headers, nil
}

func httpHeaderFromValue(value starlark.Value) (httpHeaderField, error) {
	if tuple, ok := value.(starlark.Tuple); ok {
		if len(tuple) != 2 {
			return httpHeaderField{}, fmt.Errorf("header tuples must contain exactly 2 items")
		}
		name := strings.TrimSpace(starlarkStringValue(tuple[0]))
		if name == "" {
			return httpHeaderField{}, fmt.Errorf("header name is required")
		}
		return httpHeaderField{name: name, value: starlarkStringValue(tuple[1])}, nil
	}

	nameValue, err := attrOrNone(value, "name")
	if err != nil {
		return httpHeaderField{}, err
	}
	valueValue, err := attrOrNone(value, "value")
	if err != nil {
		return httpHeaderField{}, err
	}

	name := strings.TrimSpace(starlarkStringValue(nameValue))
	if name == "" {
		return httpHeaderField{}, fmt.Errorf("header name is required")
	}
	return httpHeaderField{name: name, value: starlarkStringValue(valueValue)}, nil
}

func starlarkStringValue(value starlark.Value) string {
	if isNone(value) {
		return ""
	}
	if text, ok := starlark.AsString(value); ok {
		return text
	}
	return value.String()
}
