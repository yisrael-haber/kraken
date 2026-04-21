package script

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
	"go.starlark.net/starlark"
)

func newApplicationDNSValue(dns *layers.DNS) (starlark.Value, error) {
	if dns == nil {
		return starlark.None, nil
	}

	questions := make([]starlark.Value, 0, len(dns.Questions))
	for _, item := range dns.Questions {
		questions = append(questions, newScriptObject("buffer.dns.question", true, starlark.StringDict{
			"name":  starlark.String(string(item.Name)),
			"type":  starlark.String(item.Type.String()),
			"class": starlark.String(item.Class.String()),
		}))
	}

	answers, err := newMutableDNSRecordList(dns.Answers)
	if err != nil {
		return nil, err
	}
	authorities, err := newMutableDNSRecordList(dns.Authorities)
	if err != nil {
		return nil, err
	}
	additionals, err := newMutableDNSRecordList(dns.Additionals)
	if err != nil {
		return nil, err
	}

	return newScriptObject("buffer.dns", true, starlark.StringDict{
		"id":                 starlark.MakeUint64(uint64(dns.ID)),
		"isResponse":         starlark.Bool(dns.QR),
		"opCode":             starlark.String(dns.OpCode.String()),
		"authoritative":      starlark.Bool(dns.AA),
		"truncated":          starlark.Bool(dns.TC),
		"recursionDesired":   starlark.Bool(dns.RD),
		"recursionAvailable": starlark.Bool(dns.RA),
		"z":                  starlark.MakeUint64(uint64(dns.Z)),
		"responseCode":       starlark.String(dns.ResponseCode.String()),
		"questions":          starlark.NewList(questions),
		"answers":            answers,
		"authorities":        authorities,
		"additionals":        additionals,
	}), nil
}

func newMutableDNSRecordList(records []layers.DNSResourceRecord) (starlark.Value, error) {
	items := make([]starlark.Value, 0, len(records))
	for _, item := range records {
		value, err := newMutableDNSRecordValue(item)
		if err != nil {
			return nil, err
		}
		items = append(items, value)
	}
	return starlark.NewList(items), nil
}

func newMutableDNSRecordValue(record layers.DNSResourceRecord) (starlark.Value, error) {
	txts := make([]starlark.Value, 0, len(record.TXTs))
	for _, item := range record.TXTs {
		txts = append(txts, starlark.String(string(item)))
	}

	options := make([]starlark.Value, 0, len(record.OPT))
	for _, item := range record.OPT {
		options = append(options, newScriptObject("buffer.dns.record.opt", true, starlark.StringDict{
			"code": starlark.String(item.Code.String()),
			"data": newOwnedByteBuffer(append([]byte(nil), item.Data...)),
		}))
	}

	soa := starlark.Value(starlark.None)
	if len(record.SOA.MName) != 0 || len(record.SOA.RName) != 0 || record.SOA.Serial != 0 {
		soa = newScriptObject("buffer.dns.record.soa", true, starlark.StringDict{
			"mName":   starlark.String(string(record.SOA.MName)),
			"rName":   starlark.String(string(record.SOA.RName)),
			"serial":  starlark.MakeUint64(uint64(record.SOA.Serial)),
			"refresh": starlark.MakeUint64(uint64(record.SOA.Refresh)),
			"retry":   starlark.MakeUint64(uint64(record.SOA.Retry)),
			"expire":  starlark.MakeUint64(uint64(record.SOA.Expire)),
			"minimum": starlark.MakeUint64(uint64(record.SOA.Minimum)),
		})
	}

	mx := starlark.Value(starlark.None)
	if len(record.MX.Name) != 0 || record.MX.Preference != 0 {
		mx = newScriptObject("buffer.dns.record.mx", true, starlark.StringDict{
			"preference": starlark.MakeUint64(uint64(record.MX.Preference)),
			"name":       starlark.String(string(record.MX.Name)),
		})
	}

	srv := starlark.Value(starlark.None)
	if len(record.SRV.Name) != 0 || record.SRV.Port != 0 {
		srv = newScriptObject("buffer.dns.record.srv", true, starlark.StringDict{
			"priority": starlark.MakeUint64(uint64(record.SRV.Priority)),
			"weight":   starlark.MakeUint64(uint64(record.SRV.Weight)),
			"port":     starlark.MakeUint64(uint64(record.SRV.Port)),
			"name":     starlark.String(string(record.SRV.Name)),
		})
	}

	uri := starlark.Value(starlark.None)
	if len(record.URI.Target) != 0 || record.URI.Priority != 0 || record.URI.Weight != 0 {
		uri = newScriptObject("buffer.dns.record.uri", true, starlark.StringDict{
			"priority": starlark.MakeUint64(uint64(record.URI.Priority)),
			"weight":   starlark.MakeUint64(uint64(record.URI.Weight)),
			"target":   starlark.String(string(record.URI.Target)),
		})
	}

	ip := starlark.Value(starlark.None)
	if record.IP != nil {
		ip = starlark.String(record.IP.String())
	}

	return newScriptObject("buffer.dns.record", true, starlark.StringDict{
		"name":  starlark.String(string(record.Name)),
		"type":  starlark.String(record.Type.String()),
		"class": starlark.String(record.Class.String()),
		"ttl":   starlark.MakeUint64(uint64(record.TTL)),
		"data":  newOwnedByteBuffer(append([]byte(nil), record.Data...)),
		"ip":    ip,
		"ns":    starlark.String(string(record.NS)),
		"cname": starlark.String(string(record.CNAME)),
		"ptr":   starlark.String(string(record.PTR)),
		"txts":  starlark.NewList(txts),
		"soa":   soa,
		"mx":    mx,
		"srv":   srv,
		"uri":   uri,
		"opt":   starlark.NewList(options),
		"text":  starlark.String(dnsRecordSummary(record)),
	}), nil
}

func encodeApplicationDNSValue(value starlark.Value) ([]byte, error) {
	idValue, err := attrOrNone(value, "id")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.id: %w", err)
	}
	id, err := parseOptionalUint16(idValue)
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.id: %w", err)
	}
	isResponse, err := parseApplicationBoolField(value, "isResponse")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.isResponse: %w", err)
	}
	authoritative, err := parseApplicationBoolField(value, "authoritative")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.authoritative: %w", err)
	}
	truncated, err := parseApplicationBoolField(value, "truncated")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.truncated: %w", err)
	}
	recursionDesired, err := parseApplicationBoolField(value, "recursionDesired")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.recursionDesired: %w", err)
	}
	recursionAvailable, err := parseApplicationBoolField(value, "recursionAvailable")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.recursionAvailable: %w", err)
	}
	zValue, err := attrOrNone(value, "z")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.z: %w", err)
	}
	z, err := parseOptionalUint8Range(zValue, 0, 7)
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.z: %w", err)
	}
	opCode, err := parseDNSOpCodeValue(value, "opCode")
	if err != nil {
		return nil, err
	}
	responseCode, err := parseDNSResponseCodeValue(value, "responseCode")
	if err != nil {
		return nil, err
	}
	questions, err := parseApplicationDNSQuestions(value)
	if err != nil {
		return nil, err
	}
	answers, err := parseApplicationDNSRecords(value, "answers")
	if err != nil {
		return nil, err
	}
	authorities, err := parseApplicationDNSRecords(value, "authorities")
	if err != nil {
		return nil, err
	}
	additionals, err := parseApplicationDNSRecords(value, "additionals")
	if err != nil {
		return nil, err
	}

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[:2], valueOrZeroUint16(id))
	if valueOrFalse(isResponse) {
		header[2] |= 0x80
	}
	header[2] |= uint8(opCode&0x0f) << 3
	if valueOrFalse(authoritative) {
		header[2] |= 0x04
	}
	if valueOrFalse(truncated) {
		header[2] |= 0x02
	}
	if valueOrFalse(recursionDesired) {
		header[2] |= 0x01
	}
	if valueOrFalse(recursionAvailable) {
		header[3] |= 0x80
	}
	header[3] |= (valueOrZeroUint8(z) & 0x7) << 4
	header[3] |= uint8(responseCode & 0x0f)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(questions)))
	binary.BigEndian.PutUint16(header[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(header[8:10], uint16(len(authorities)))
	binary.BigEndian.PutUint16(header[10:12], uint16(len(additionals)))

	var buffer bytes.Buffer
	buffer.Write(header)
	for _, item := range questions {
		writeApplicationDNSName(&buffer, item.Name)
		_ = binary.Write(&buffer, binary.BigEndian, uint16(item.Type))
		_ = binary.Write(&buffer, binary.BigEndian, uint16(item.Class))
	}
	for _, section := range [][]applicationDNSRecord{answers, authorities, additionals} {
		for _, item := range section {
			writeApplicationDNSName(&buffer, item.Name)
			_ = binary.Write(&buffer, binary.BigEndian, uint16(item.Type))
			_ = binary.Write(&buffer, binary.BigEndian, uint16(item.Class))
			_ = binary.Write(&buffer, binary.BigEndian, item.TTL)
			_ = binary.Write(&buffer, binary.BigEndian, uint16(len(item.RData)))
			buffer.Write(item.RData)
		}
	}

	return buffer.Bytes(), nil
}

type applicationDNSQuestion struct {
	Name  string
	Type  layers.DNSType
	Class layers.DNSClass
}

type applicationDNSRecord struct {
	Name  string
	Type  layers.DNSType
	Class layers.DNSClass
	TTL   uint32
	RData []byte
}

func parseApplicationDNSQuestions(value starlark.Value) ([]applicationDNSQuestion, error) {
	itemsValue, err := attrOrNone(value, "questions")
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.questions: %w", err)
	}
	items, err := iterableValues(itemsValue)
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.questions: %w", err)
	}
	questions := make([]applicationDNSQuestion, 0, len(items))
	for index, item := range items {
		nameValue, err := attrOrNone(item, "name")
		if err != nil {
			return nil, fmt.Errorf("buffer.dns.questions[%d].name: %w", index, err)
		}
		typeValue, err := attrOrNone(item, "type")
		if err != nil {
			return nil, fmt.Errorf("buffer.dns.questions[%d].type: %w", index, err)
		}
		classValue, err := attrOrNone(item, "class")
		if err != nil {
			return nil, fmt.Errorf("buffer.dns.questions[%d].class: %w", index, err)
		}

		recordType, err := parseDNSType(typeValue)
		if err != nil {
			return nil, fmt.Errorf("buffer.dns.questions[%d].type: %w", index, err)
		}
		recordClass, err := parseDNSClass(classValue)
		if err != nil {
			return nil, fmt.Errorf("buffer.dns.questions[%d].class: %w", index, err)
		}
		questions = append(questions, applicationDNSQuestion{
			Name:  stringValue(nameValue),
			Type:  recordType,
			Class: recordClass,
		})
	}
	return questions, nil
}

func parseApplicationDNSRecords(value starlark.Value, field string) ([]applicationDNSRecord, error) {
	itemsValue, err := attrOrNone(value, field)
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.%s: %w", field, err)
	}
	items, err := iterableValues(itemsValue)
	if err != nil {
		return nil, fmt.Errorf("buffer.dns.%s: %w", field, err)
	}
	records := make([]applicationDNSRecord, 0, len(items))
	for index, item := range items {
		record, err := parseApplicationDNSRecord(item)
		if err != nil {
			return nil, fmt.Errorf("buffer.dns.%s[%d]: %w", field, index, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func parseApplicationDNSRecord(value starlark.Value) (applicationDNSRecord, error) {
	nameValue, err := attrOrNone(value, "name")
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("name: %w", err)
	}
	typeValue, err := attrOrNone(value, "type")
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("type: %w", err)
	}
	classValue, err := attrOrNone(value, "class")
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("class: %w", err)
	}
	ttlValue, err := attrOrNone(value, "ttl")
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("ttl: %w", err)
	}
	recordType, err := parseDNSType(typeValue)
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("type: %w", err)
	}
	recordClass, err := parseDNSClass(classValue)
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("class: %w", err)
	}
	ttl, err := parseOptionalUint32(ttlValue)
	if err != nil {
		return applicationDNSRecord{}, fmt.Errorf("ttl: %w", err)
	}
	rdata, err := applicationDNSRData(recordType, value)
	if err != nil {
		return applicationDNSRecord{}, err
	}
	return applicationDNSRecord{
		Name:  stringValue(nameValue),
		Type:  recordType,
		Class: recordClass,
		TTL:   valueOrZeroUint32(ttl),
		RData: rdata,
	}, nil
}

func applicationDNSRData(recordType layers.DNSType, value starlark.Value) ([]byte, error) {
	dataValue, err := attrOrNone(value, "data")
	if err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	rawData, err := parseOptionalBytes(dataValue)
	if err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}

	switch recordType {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		ipValue, err := attrOrNone(value, "ip")
		if err != nil {
			return nil, fmt.Errorf("ip: %w", err)
		}
		ipText := stringValue(ipValue)
		if ipText == "" {
			return rawData, nil
		}
		ip := net.ParseIP(ipText)
		if ip == nil {
			return nil, fmt.Errorf("ip: invalid IP %q", ipText)
		}
		if recordType == layers.DNSTypeA {
			ip = ip.To4()
			if ip == nil {
				return nil, fmt.Errorf("ip: IPv4 address is required")
			}
		}
		return append([]byte(nil), ip...), nil
	case layers.DNSTypeNS:
		return applicationDNSNameField(value, "ns", rawData)
	case layers.DNSTypeCNAME:
		return applicationDNSNameField(value, "cname", rawData)
	case layers.DNSTypePTR:
		return applicationDNSNameField(value, "ptr", rawData)
	case layers.DNSTypeTXT, layers.DNSTypeHINFO:
		txtsValue, err := attrOrNone(value, "txts")
		if err != nil {
			return nil, fmt.Errorf("txts: %w", err)
		}
		txtItems, err := iterableValues(txtsValue)
		if err != nil || len(txtItems) == 0 {
			return rawData, nil
		}
		var buffer bytes.Buffer
		for index, item := range txtItems {
			text := stringValue(item)
			if len(text) > 255 {
				return nil, fmt.Errorf("txts[%d]: must be at most 255 bytes", index)
			}
			buffer.WriteByte(byte(len(text)))
			buffer.WriteString(text)
		}
		return buffer.Bytes(), nil
	case layers.DNSTypeSOA:
		soaValue, err := attrOrNone(value, "soa")
		if err != nil {
			return nil, fmt.Errorf("soa: %w", err)
		}
		if isNone(soaValue) {
			return rawData, nil
		}
		var buffer bytes.Buffer
		writeApplicationDNSName(&buffer, stringValue(mustAttrOrNone(soaValue, "mName")))
		writeApplicationDNSName(&buffer, stringValue(mustAttrOrNone(soaValue, "rName")))
		writeApplicationUint32(&buffer, mustUint32(soaValue, "serial"))
		writeApplicationUint32(&buffer, mustUint32(soaValue, "refresh"))
		writeApplicationUint32(&buffer, mustUint32(soaValue, "retry"))
		writeApplicationUint32(&buffer, mustUint32(soaValue, "expire"))
		writeApplicationUint32(&buffer, mustUint32(soaValue, "minimum"))
		return buffer.Bytes(), nil
	case layers.DNSTypeMX:
		mxValue, err := attrOrNone(value, "mx")
		if err != nil {
			return nil, fmt.Errorf("mx: %w", err)
		}
		if isNone(mxValue) {
			return rawData, nil
		}
		var buffer bytes.Buffer
		writeApplicationUint16(&buffer, mustUint16(mxValue, "preference"))
		writeApplicationDNSName(&buffer, stringValue(mustAttrOrNone(mxValue, "name")))
		return buffer.Bytes(), nil
	case layers.DNSTypeSRV:
		srvValue, err := attrOrNone(value, "srv")
		if err != nil {
			return nil, fmt.Errorf("srv: %w", err)
		}
		if isNone(srvValue) {
			return rawData, nil
		}
		var buffer bytes.Buffer
		writeApplicationUint16(&buffer, mustUint16(srvValue, "priority"))
		writeApplicationUint16(&buffer, mustUint16(srvValue, "weight"))
		writeApplicationUint16(&buffer, mustUint16(srvValue, "port"))
		writeApplicationDNSName(&buffer, stringValue(mustAttrOrNone(srvValue, "name")))
		return buffer.Bytes(), nil
	case layers.DNSTypeURI:
		uriValue, err := attrOrNone(value, "uri")
		if err != nil {
			return nil, fmt.Errorf("uri: %w", err)
		}
		if isNone(uriValue) {
			return rawData, nil
		}
		var buffer bytes.Buffer
		writeApplicationUint16(&buffer, mustUint16(uriValue, "priority"))
		writeApplicationUint16(&buffer, mustUint16(uriValue, "weight"))
		buffer.WriteString(stringValue(mustAttrOrNone(uriValue, "target")))
		return buffer.Bytes(), nil
	case layers.DNSTypeOPT:
		optValue, err := attrOrNone(value, "opt")
		if err != nil {
			return nil, fmt.Errorf("opt: %w", err)
		}
		optItems, err := iterableValues(optValue)
		if err != nil || len(optItems) == 0 {
			return rawData, nil
		}
		var buffer bytes.Buffer
		for index, item := range optItems {
			code, err := parseDNSOptionCode(mustAttrOrNone(item, "code"))
			if err != nil {
				return nil, fmt.Errorf("opt[%d].code: %w", index, err)
			}
			optionData, err := parseOptionalBytes(mustAttrOrNone(item, "data"))
			if err != nil {
				return nil, fmt.Errorf("opt[%d].data: %w", index, err)
			}
			writeApplicationUint16(&buffer, uint16(code))
			writeApplicationUint16(&buffer, uint16(len(optionData)))
			buffer.Write(optionData)
		}
		return buffer.Bytes(), nil
	default:
		return rawData, nil
	}
}

func applicationDNSNameField(value starlark.Value, field string, fallback []byte) ([]byte, error) {
	fieldValue, err := attrOrNone(value, field)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if text := stringValue(fieldValue); text != "" {
		var buffer bytes.Buffer
		writeApplicationDNSName(&buffer, text)
		return buffer.Bytes(), nil
	}
	return fallback, nil
}

func writeApplicationDNSName(buffer *bytes.Buffer, name string) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		buffer.WriteByte(0)
		return
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		buffer.WriteByte(byte(len(label)))
		buffer.WriteString(label)
	}
	buffer.WriteByte(0)
}

func parseApplicationBoolField(value starlark.Value, name string) (*bool, error) {
	fieldValue, err := attrOrNone(value, name)
	if err != nil {
		return nil, err
	}
	return parseOptionalBool(fieldValue)
}

func parseDNSOpCodeValue(value starlark.Value, name string) (layers.DNSOpCode, error) {
	fieldValue, err := attrOrNone(value, name)
	if err != nil {
		return 0, fmt.Errorf("buffer.dns.%s: %w", name, err)
	}
	return parseDNSOpCode(fieldValue)
}

func parseDNSResponseCodeValue(value starlark.Value, name string) (layers.DNSResponseCode, error) {
	fieldValue, err := attrOrNone(value, name)
	if err != nil {
		return 0, fmt.Errorf("buffer.dns.%s: %w", name, err)
	}
	return parseDNSResponseCode(fieldValue)
}

func parseDNSType(value starlark.Value) (layers.DNSType, error) {
	if text, ok := starlark.AsString(value); ok {
		switch strings.ToUpper(strings.TrimSpace(text)) {
		case "A":
			return layers.DNSTypeA, nil
		case "NS":
			return layers.DNSTypeNS, nil
		case "CNAME":
			return layers.DNSTypeCNAME, nil
		case "SOA":
			return layers.DNSTypeSOA, nil
		case "PTR":
			return layers.DNSTypePTR, nil
		case "MX":
			return layers.DNSTypeMX, nil
		case "TXT":
			return layers.DNSTypeTXT, nil
		case "AAAA":
			return layers.DNSTypeAAAA, nil
		case "SRV":
			return layers.DNSTypeSRV, nil
		case "OPT":
			return layers.DNSTypeOPT, nil
		case "URI":
			return layers.DNSTypeURI, nil
		case "HINFO":
			return layers.DNSTypeHINFO, nil
		}
	}
	number, err := integerValue(value)
	if err != nil {
		return 0, fmt.Errorf("must be a DNS type name or number")
	}
	return layers.DNSType(number), nil
}

func parseDNSClass(value starlark.Value) (layers.DNSClass, error) {
	if text, ok := starlark.AsString(value); ok {
		switch strings.ToUpper(strings.TrimSpace(text)) {
		case "IN":
			return layers.DNSClassIN, nil
		case "CS":
			return layers.DNSClassCS, nil
		case "CH":
			return layers.DNSClassCH, nil
		case "HS":
			return layers.DNSClassHS, nil
		case "ANY":
			return layers.DNSClassAny, nil
		}
	}
	number, err := integerValue(value)
	if err != nil {
		return 0, fmt.Errorf("must be a DNS class name or number")
	}
	return layers.DNSClass(number), nil
}

func parseDNSOpCode(value starlark.Value) (layers.DNSOpCode, error) {
	if text, ok := starlark.AsString(value); ok {
		switch strings.TrimSpace(text) {
		case "Query":
			return layers.DNSOpCodeQuery, nil
		case "IQuery":
			return layers.DNSOpCodeIQuery, nil
		case "Status":
			return layers.DNSOpCodeStatus, nil
		case "Notify":
			return layers.DNSOpCodeNotify, nil
		case "Update":
			return layers.DNSOpCodeUpdate, nil
		}
	}
	number, err := integerValue(value)
	if err != nil {
		return 0, fmt.Errorf("must be a DNS opCode name or number")
	}
	return layers.DNSOpCode(number), nil
}

func parseDNSResponseCode(value starlark.Value) (layers.DNSResponseCode, error) {
	if text, ok := starlark.AsString(value); ok {
		switch strings.TrimSpace(text) {
		case "No Error":
			return layers.DNSResponseCodeNoErr, nil
		case "Format Error":
			return layers.DNSResponseCodeFormErr, nil
		case "Server Failure":
			return layers.DNSResponseCodeServFail, nil
		case "Non-Existent Domain":
			return layers.DNSResponseCodeNXDomain, nil
		case "Not Implemented":
			return layers.DNSResponseCodeNotImp, nil
		case "Query Refused":
			return layers.DNSResponseCodeRefused, nil
		}
	}
	number, err := integerValue(value)
	if err != nil {
		return 0, fmt.Errorf("must be a DNS responseCode name or number")
	}
	return layers.DNSResponseCode(number), nil
}

func parseDNSOptionCode(value starlark.Value) (layers.DNSOptionCode, error) {
	if text, ok := starlark.AsString(value); ok {
		switch strings.TrimSpace(text) {
		case "NSID":
			return layers.DNSOptionCodeNSID, nil
		case "DAU":
			return layers.DNSOptionCodeDAU, nil
		case "DHU":
			return layers.DNSOptionCodeDHU, nil
		case "N3U":
			return layers.DNSOptionCodeN3U, nil
		case "EDNSClientSubnet":
			return layers.DNSOptionCodeEDNSClientSubnet, nil
		case "EDNSExpire":
			return layers.DNSOptionCodeEDNSExpire, nil
		case "Cookie":
			return layers.DNSOptionCodeCookie, nil
		case "EDNSKeepAlive":
			return layers.DNSOptionCodeEDNSKeepAlive, nil
		case "CodePadding":
			return layers.DNSOptionCodePadding, nil
		case "CodeChain":
			return layers.DNSOptionCodeChain, nil
		case "CodeEDNSKeyTag":
			return layers.DNSOptionCodeEDNSKeyTag, nil
		case "EDNSClientTag":
			return layers.DNSOptionCodeEDNSClientTag, nil
		case "EDNSServerTag":
			return layers.DNSOptionCodeEDNSServerTag, nil
		case "DeviceID":
			return layers.DNSOptionCodeDeviceID, nil
		}
	}
	number, err := integerValue(value)
	if err != nil {
		return 0, fmt.Errorf("must be a DNS option code name or number")
	}
	return layers.DNSOptionCode(number), nil
}

func newApplicationTLSValue(payload []byte) (starlark.Value, error) {
	records, err := parseApplicationTLSRecords(payload)
	if err != nil {
		return nil, nil
	}
	items := make([]starlark.Value, 0, len(records))
	for _, item := range records {
		items = append(items, item)
	}
	return newScriptObject("buffer.tls", true, starlark.StringDict{
		"records": starlark.NewList(items),
	}), nil
}

func parseApplicationTLSRecords(payload []byte) ([]starlark.Value, error) {
	records := make([]starlark.Value, 0)
	for offset := 0; offset < len(payload); {
		if len(payload)-offset < 5 {
			return nil, fmt.Errorf("TLS record too short")
		}
		contentType := payload[offset]
		version := binary.BigEndian.Uint16(payload[offset+1 : offset+3])
		length := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
		if len(payload)-offset-5 < length {
			return nil, fmt.Errorf("TLS record length mismatch")
		}
		recordPayload := append([]byte(nil), payload[offset+5:offset+5+length]...)
		fields := starlark.StringDict{
			"contentType": starlark.MakeUint64(uint64(contentType)),
			"version":     starlark.MakeUint64(uint64(version)),
			"length":      starlark.MakeUint64(uint64(length)),
			"payload":     newOwnedByteBuffer(recordPayload),
		}
		if contentType == uint8(layers.TLSChangeCipherSpec) && len(recordPayload) == 1 {
			fields["message"] = starlark.MakeUint64(uint64(recordPayload[0]))
		}
		if contentType == uint8(layers.TLSAlert) && len(recordPayload) == 2 {
			fields["level"] = starlark.MakeUint64(uint64(recordPayload[0]))
			fields["description"] = starlark.MakeUint64(uint64(recordPayload[1]))
		}
		records = append(records, newScriptObject("buffer.tls.record", true, fields))
		offset += 5 + length
	}
	return records, nil
}

func encodeApplicationTLSValue(value starlark.Value) ([]byte, error) {
	recordsValue, err := attrOrNone(value, "records")
	if err != nil {
		return nil, fmt.Errorf("buffer.tls.records: %w", err)
	}
	recordItems, err := iterableValues(recordsValue)
	if err != nil {
		return nil, fmt.Errorf("buffer.tls.records: %w", err)
	}

	var buffer bytes.Buffer
	for index, item := range recordItems {
		contentType, err := parseOptionalUint8(mustAttrOrNone(item, "contentType"))
		if err != nil {
			return nil, fmt.Errorf("buffer.tls.records[%d].contentType: %w", index, err)
		}
		version, err := parseOptionalUint16(mustAttrOrNone(item, "version"))
		if err != nil {
			return nil, fmt.Errorf("buffer.tls.records[%d].version: %w", index, err)
		}
		payload, err := parseOptionalBytes(mustAttrOrNone(item, "payload"))
		if err != nil {
			return nil, fmt.Errorf("buffer.tls.records[%d].payload: %w", index, err)
		}
		if contentType == nil || version == nil {
			return nil, fmt.Errorf("buffer.tls.records[%d]: contentType and version are required", index)
		}
		switch *contentType {
		case uint8(layers.TLSChangeCipherSpec):
			if message, err := parseOptionalUint8(mustAttrOrNone(item, "message")); err == nil && message != nil {
				payload = []byte{*message}
			}
		case uint8(layers.TLSAlert):
			level, levelErr := parseOptionalUint8(mustAttrOrNone(item, "level"))
			description, descErr := parseOptionalUint8(mustAttrOrNone(item, "description"))
			if levelErr == nil && descErr == nil && level != nil && description != nil {
				payload = []byte{*level, *description}
			}
		}
		buffer.WriteByte(*contentType)
		writeApplicationUint16(&buffer, *version)
		writeApplicationUint16(&buffer, uint16(len(payload)))
		buffer.Write(payload)
	}
	return buffer.Bytes(), nil
}

func newApplicationModbusValue(modbus *layers.ModbusTCP) (starlark.Value, error) {
	if modbus == nil {
		return starlark.None, nil
	}
	return newScriptObject("buffer.modbusTCP", true, starlark.StringDict{
		"transactionIdentifier": starlark.MakeUint64(uint64(modbus.TransactionIdentifier)),
		"protocolIdentifier":    starlark.MakeUint64(uint64(modbus.ProtocolIdentifier)),
		"length":                starlark.MakeUint64(uint64(modbus.Length)),
		"unitIdentifier":        starlark.MakeUint64(uint64(modbus.UnitIdentifier)),
		"payload":               newOwnedByteBuffer(append([]byte(nil), modbus.BaseLayer.Payload...)),
	}), nil
}

func encodeApplicationModbusValue(value starlark.Value) ([]byte, error) {
	transactionIdentifier, err := parseOptionalUint16(mustAttrOrNone(value, "transactionIdentifier"))
	if err != nil {
		return nil, fmt.Errorf("buffer.modbusTCP.transactionIdentifier: %w", err)
	}
	protocolIdentifier, err := parseOptionalUint16(mustAttrOrNone(value, "protocolIdentifier"))
	if err != nil {
		return nil, fmt.Errorf("buffer.modbusTCP.protocolIdentifier: %w", err)
	}
	unitIdentifier, err := parseOptionalUint8(mustAttrOrNone(value, "unitIdentifier"))
	if err != nil {
		return nil, fmt.Errorf("buffer.modbusTCP.unitIdentifier: %w", err)
	}
	payload, err := parseOptionalBytes(mustAttrOrNone(value, "payload"))
	if err != nil {
		return nil, fmt.Errorf("buffer.modbusTCP.payload: %w", err)
	}

	frame := make([]byte, 7+len(payload))
	binary.BigEndian.PutUint16(frame[:2], valueOrZeroUint16(transactionIdentifier))
	binary.BigEndian.PutUint16(frame[2:4], valueOrZeroUint16(protocolIdentifier))
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)+1))
	frame[6] = valueOrZeroUint8(unitIdentifier)
	copy(frame[7:], payload)
	return frame, nil
}

func iterableValues(value starlark.Value) ([]starlark.Value, error) {
	if isNone(value) {
		return nil, nil
	}
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("must be iterable")
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	items := make([]starlark.Value, 0, max(0, starlark.Len(value)))
	var item starlark.Value
	for iterator.Next(&item) {
		items = append(items, item)
	}
	return items, nil
}

func writeApplicationUint16(buffer *bytes.Buffer, value uint16) {
	var bytes [2]byte
	binary.BigEndian.PutUint16(bytes[:], value)
	buffer.Write(bytes[:])
}

func writeApplicationUint32(buffer *bytes.Buffer, value uint32) {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	buffer.Write(bytes[:])
}

func mustAttrOrNone(value starlark.Value, name string) starlark.Value {
	attr, err := attrOrNone(value, name)
	if err != nil {
		return starlark.None
	}
	return attr
}

func mustUint16(value starlark.Value, name string) uint16 {
	number, _ := parseOptionalUint16(mustAttrOrNone(value, name))
	return valueOrZeroUint16(number)
}

func mustUint32(value starlark.Value, name string) uint32 {
	number, _ := parseOptionalUint32(mustAttrOrNone(value, name))
	return valueOrZeroUint32(number)
}

func parseOptionalUint32(value starlark.Value) (*uint32, error) {
	if isNone(value) {
		return nil, nil
	}
	number, err := integerValue(value)
	if err != nil {
		return nil, err
	}
	if number < 0 || number > 4294967295 {
		return nil, fmt.Errorf("must be between 0 and 4294967295")
	}
	converted := uint32(number)
	return &converted, nil
}

func valueOrZeroUint32(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}

func dnsRecordSummary(record layers.DNSResourceRecord) string {
	switch {
	case len(record.CNAME) != 0:
		return string(record.CNAME)
	case len(record.NS) != 0:
		return string(record.NS)
	case len(record.PTR) != 0:
		return string(record.PTR)
	case len(record.TXTs) != 0:
		parts := make([]string, 0, len(record.TXTs))
		for _, item := range record.TXTs {
			parts = append(parts, string(item))
		}
		return strings.Join(parts, "\n")
	case len(record.URI.Target) != 0:
		return string(record.URI.Target)
	case len(record.SRV.Name) != 0:
		return string(record.SRV.Name)
	case record.IP != nil:
		return record.IP.String()
	default:
		return ""
	}
}
