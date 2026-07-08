package script

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/mandiant/gopacket/pkg/ntlm"
	"github.com/mandiant/gopacket/pkg/security"
	"github.com/mandiant/gopacket/pkg/tds"
	"github.com/mandiant/gopacket/pkg/utf16le"
	"go.starlark.net/starlark"
)

func buildWindowsModule() starlark.Value {
	return &scriptObject{typeName: "windows", fields: starlark.StringDict{
		"sid":      buildWindowsSIDObject(),
		"security": buildWindowsSecurityObject(),
		"ntlm":     buildWindowsNTLMObject(),
		"tds":      buildWindowsTDSObject(),
		"utf16le":  buildWindowsUTF16LEObject(),
	}}
}

func buildWindowsUTF16LEObject() starlark.Value {
	return &scriptObject{typeName: "windows.utf16le", fields: starlark.StringDict{
		"encode": starlark.NewBuiltin("windows.utf16le.encode", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var text string
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
				return nil, err
			}
			return &byteBuffer{data: utf16le.EncodeStringToBytes(text)}, nil
		}),
		"decode": starlark.NewBuiltin("windows.utf16le.decode", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var payload starlark.Value
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &payload); err != nil {
				return nil, err
			}
			data, err := byteSliceFromValue(payload)
			if err != nil {
				return nil, err
			}
			return starlark.String(utf16le.DecodeToString(data)), nil
		}),
	}}
}

func buildWindowsSIDObject() starlark.Value {
	return &scriptObject{typeName: "windows.sid", fields: starlark.StringDict{
		"parse": starlark.NewBuiltin("windows.sid.parse", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var value starlark.Value
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &value); err != nil {
				return nil, err
			}
			return windowsSIDFromValue(value)
		}),
	}}
}

func windowsSIDFromValue(value starlark.Value) (*windowsSIDValue, error) {
	if text, ok := starlark.AsString(value); ok {
		sid, err := security.ParseSID(text)
		if err != nil {
			return nil, err
		}
		return &windowsSIDValue{sid: sid}, nil
	}
	data, err := byteSliceFromValue(value)
	if err != nil {
		return nil, err
	}
	sid, _, err := security.ParseSIDBytes(data)
	if err != nil {
		return nil, err
	}
	return &windowsSIDValue{sid: sid}, nil
}

type windowsSIDValue struct {
	sid *security.SID
}

func (value *windowsSIDValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "text":
		return starlark.String(value.sid.String()), nil
	case "bytes":
		return &byteBuffer{data: value.sid.Marshal()}, nil
	case "revision":
		return starlark.MakeInt(int(value.sid.Revision)), nil
	case "authority":
		var buffer [8]byte
		copy(buffer[2:], value.sid.IdentifierAuthority[:])
		return starlark.MakeUint64(binary.BigEndian.Uint64(buffer[:])), nil
	case "subAuthorities":
		items := make([]starlark.Value, 0, len(value.sid.SubAuthority))
		for _, item := range value.sid.SubAuthority {
			items = append(items, starlark.MakeUint64(uint64(item)))
		}
		return starlark.NewList(items), nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (*windowsSIDValue) AttrNames() []string {
	return []string{"text", "bytes", "revision", "authority", "subAuthorities"}
}
func (value *windowsSIDValue) String() string { return value.sid.String() }
func (*windowsSIDValue) Type() string         { return "windows.sid.value" }
func (*windowsSIDValue) Freeze()              {}
func (*windowsSIDValue) Truth() starlark.Bool { return true }
func (value *windowsSIDValue) Hash() (uint32, error) {
	return starlark.String(value.sid.String()).Hash()
}

func buildWindowsSecurityObject() starlark.Value {
	return &scriptObject{typeName: "windows.security", fields: starlark.StringDict{
		"parse_descriptor": starlark.NewBuiltin("windows.security.parse_descriptor", parseWindowsSecurityDescriptor),
		"parse_acl":        starlark.NewBuiltin("windows.security.parse_acl", parseWindowsACL),
		"parse_ace":        starlark.NewBuiltin("windows.security.parse_ace", parseWindowsACE),
		"access_mask_text": starlark.NewBuiltin("windows.security.access_mask_text", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var maskValue starlark.Value
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &maskValue); err != nil {
				return nil, err
			}
			mask, err := integerInRange(maskValue, 0, 0xffffffff)
			if err != nil {
				return nil, fmt.Errorf("access mask: %w", err)
			}
			return starlark.String(security.FormatAccessMask(uint32(mask))), nil
		}),
	}}
}

func parseWindowsSecurityDescriptor(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := oneBytesArg(builtin.Name(), args, kwargs)
	if err != nil {
		return nil, err
	}
	descriptor, err := security.ParseSecurityDescriptor(data)
	if err != nil {
		return nil, err
	}
	return &windowsSecurityDescriptorValue{descriptor: descriptor}, nil
}

func parseWindowsACL(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := oneBytesArg(builtin.Name(), args, kwargs)
	if err != nil {
		return nil, err
	}
	acl, err := security.ParseACL(data)
	if err != nil {
		return nil, err
	}
	return &windowsACLValue{acl: acl}, nil
}

func parseWindowsACE(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := oneBytesArg(builtin.Name(), args, kwargs)
	if err != nil {
		return nil, err
	}
	ace, consumed, err := security.ParseACE(data)
	if err != nil {
		return nil, err
	}
	return &windowsACEValue{ace: ace, consumed: consumed}, nil
}

type windowsSecurityDescriptorValue struct {
	descriptor *security.SecurityDescriptor
}

func (value *windowsSecurityDescriptorValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "revision":
		return starlark.MakeInt(int(value.descriptor.Revision)), nil
	case "control":
		return starlark.MakeUint64(uint64(value.descriptor.Control)), nil
	case "owner":
		return sidOrNone(value.descriptor.Owner), nil
	case "group":
		return sidOrNone(value.descriptor.Group), nil
	case "sacl":
		return aclOrNone(value.descriptor.SACL), nil
	case "dacl":
		return aclOrNone(value.descriptor.DACL), nil
	case "bytes":
		return &byteBuffer{data: value.descriptor.Marshal()}, nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (*windowsSecurityDescriptorValue) AttrNames() []string {
	return []string{"revision", "control", "owner", "group", "sacl", "dacl", "bytes"}
}
func (*windowsSecurityDescriptorValue) String() string       { return "<windows.security.descriptor>" }
func (*windowsSecurityDescriptorValue) Type() string         { return "windows.security.descriptor" }
func (*windowsSecurityDescriptorValue) Freeze()              {}
func (*windowsSecurityDescriptorValue) Truth() starlark.Bool { return true }
func (value *windowsSecurityDescriptorValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

type windowsACLValue struct {
	acl *security.ACL
}

func (value *windowsACLValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "revision":
		return starlark.MakeInt(int(value.acl.AclRevision)), nil
	case "aceCount":
		return starlark.MakeInt(len(value.acl.ACEs)), nil
	case "aces":
		items := make([]starlark.Value, 0, len(value.acl.ACEs))
		for _, ace := range value.acl.ACEs {
			items = append(items, &windowsACEValue{ace: ace})
		}
		return starlark.NewList(items), nil
	case "bytes":
		return &byteBuffer{data: value.acl.Marshal()}, nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (*windowsACLValue) AttrNames() []string {
	return []string{"revision", "aceCount", "aces", "bytes"}
}
func (*windowsACLValue) String() string       { return "<windows.security.acl>" }
func (*windowsACLValue) Type() string         { return "windows.security.acl" }
func (*windowsACLValue) Freeze()              {}
func (*windowsACLValue) Truth() starlark.Bool { return true }
func (value *windowsACLValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

type windowsACEValue struct {
	ace      *security.ACE
	consumed int
}

func (value *windowsACEValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "type":
		return starlark.MakeInt(int(value.ace.Type)), nil
	case "flags":
		return starlark.MakeInt(int(value.ace.Flags)), nil
	case "mask":
		return starlark.MakeUint64(uint64(value.ace.Mask)), nil
	case "maskText":
		return starlark.String(security.FormatAccessMask(value.ace.Mask)), nil
	case "sid":
		return sidOrNone(value.ace.SID), nil
	case "text":
		return starlark.String(security.FormatACE(value.ace, nil)), nil
	case "bytes":
		return &byteBuffer{data: value.ace.Marshal()}, nil
	case "consumed":
		return starlark.MakeInt(value.consumed), nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (*windowsACEValue) AttrNames() []string {
	return []string{"type", "flags", "mask", "maskText", "sid", "text", "bytes", "consumed"}
}
func (*windowsACEValue) String() string       { return "<windows.security.ace>" }
func (*windowsACEValue) Type() string         { return "windows.security.ace" }
func (*windowsACEValue) Freeze()              {}
func (*windowsACEValue) Truth() starlark.Bool { return true }
func (value *windowsACEValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

func sidOrNone(sid *security.SID) starlark.Value {
	if sid == nil {
		return starlark.None
	}
	return &windowsSIDValue{sid: sid}
}

func aclOrNone(acl *security.ACL) starlark.Value {
	if acl == nil {
		return starlark.None
	}
	return &windowsACLValue{acl: acl}
}

func buildWindowsNTLMObject() starlark.Value {
	return &scriptObject{typeName: "windows.ntlm", fields: starlark.StringDict{
		"client": starlark.NewBuiltin("windows.ntlm.client", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var user, password, domain, workstation, hashText, targetSPN string
			if err := starlark.UnpackArgs(builtin.Name(), args, kwargs,
				"user?", &user,
				"password?", &password,
				"domain?", &domain,
				"workstation?", &workstation,
				"hash?", &hashText,
				"target_spn?", &targetSPN,
			); err != nil {
				return nil, err
			}
			var hash []byte
			if hashText != "" {
				decoded, err := parseNTLMHash(hashText)
				if err != nil {
					return nil, err
				}
				hash = decoded
			}
			return &windowsNTLMClientValue{client: &ntlm.Client{
				User:        user,
				Password:    password,
				Domain:      domain,
				Workstation: workstation,
				Hash:        hash,
				TargetSPN:   targetSPN,
			}}, nil
		}),
	}}
}

type windowsNTLMClientValue struct {
	client *ntlm.Client
}

func (value *windowsNTLMClientValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "negotiate":
		return starlark.NewBuiltin("windows.ntlm.client.negotiate", value.negotiate), nil
	case "authenticate":
		return starlark.NewBuiltin("windows.ntlm.client.authenticate", value.authenticate), nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (*windowsNTLMClientValue) AttrNames() []string  { return []string{"negotiate", "authenticate"} }
func (*windowsNTLMClientValue) String() string       { return "<windows.ntlm.client>" }
func (*windowsNTLMClientValue) Type() string         { return "windows.ntlm.client" }
func (*windowsNTLMClientValue) Freeze()              {}
func (*windowsNTLMClientValue) Truth() starlark.Bool { return true }
func (value *windowsNTLMClientValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

func (value *windowsNTLMClientValue) negotiate(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	payload, err := value.client.Negotiate()
	if err != nil {
		return nil, err
	}
	return &byteBuffer{data: payload}, nil
}

func (value *windowsNTLMClientValue) authenticate(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	challenge, err := oneBytesArg(builtin.Name(), args, kwargs)
	if err != nil {
		return nil, err
	}
	payload, err := value.client.Authenticate(challenge)
	if err != nil {
		return nil, err
	}
	return &byteBuffer{data: payload}, nil
}

func parseNTLMHash(value string) ([]byte, error) {
	if len(value) == 65 && value[32] == ':' {
		value = value[33:]
	}
	if len(value) == 33 && value[0] == ':' {
		value = value[1:]
	}
	hash, err := hex.DecodeString(value)
	if err != nil || len(hash) != 16 {
		return nil, fmt.Errorf("ntlm hash must be 16 raw bytes encoded as 32 hex characters")
	}
	return hash, nil
}

func buildWindowsTDSObject() starlark.Value {
	return &scriptObject{typeName: "windows.tds", fields: starlark.StringDict{
		"packet":         starlark.NewBuiltin("windows.tds.packet", makeTDSPacket),
		"parse_packet":   starlark.NewBuiltin("windows.tds.parse_packet", parseTDSPacket),
		"prelogin":       starlark.NewBuiltin("windows.tds.prelogin", makeTDSPrelogin),
		"parse_prelogin": starlark.NewBuiltin("windows.tds.parse_prelogin", parseTDSPrelogin),
		"type_prelogin":  starlark.MakeInt(tds.TDSPreLogin),
		"type_login7":    starlark.MakeInt(tds.TDSLogin7),
		"type_tabular":   starlark.MakeInt(tds.TDSTabular),
		"status_eom":     starlark.MakeInt(tds.TDSStatusEOM),
	}}
}

func makeTDSPacket(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var packetType, status, spid, packetID, window int
	var dataValue starlark.Value = starlark.None
	status = tds.TDSStatusEOM
	packetID = 1
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs,
		"type", &packetType,
		"data?", &dataValue,
		"status?", &status,
		"spid?", &spid,
		"packet_id?", &packetID,
		"window?", &window,
	); err != nil {
		return nil, err
	}
	data, err := byteSliceFromValue(dataValue)
	if err != nil {
		return nil, err
	}
	packet := &tds.TDSPacket{
		Type:     uint8(packetType),
		Status:   uint8(status),
		SPID:     uint16(spid),
		PacketID: uint8(packetID),
		Window:   uint8(window),
		Data:     data,
	}
	return &byteBuffer{data: packet.Marshal()}, nil
}

func parseTDSPacket(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := oneBytesArg(builtin.Name(), args, kwargs)
	if err != nil {
		return nil, err
	}
	var packet tds.TDSPacket
	if err := packet.Unmarshal(data); err != nil {
		return nil, err
	}
	return &scriptObject{typeName: "windows.tds.packet", fields: starlark.StringDict{
		"type":      starlark.MakeInt(int(packet.Type)),
		"status":    starlark.MakeInt(int(packet.Status)),
		"length":    starlark.MakeInt(int(packet.Length)),
		"spid":      starlark.MakeInt(int(packet.SPID)),
		"packet_id": starlark.MakeInt(int(packet.PacketID)),
		"window":    starlark.MakeInt(int(packet.Window)),
		"data":      &byteBuffer{data: packet.Data},
	}}, nil
}

func makeTDSPrelogin(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var versionValue starlark.Value = starlark.None
	var encryption, threadID int
	var instance string
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs,
		"version?", &versionValue,
		"encryption?", &encryption,
		"instance?", &instance,
		"thread_id?", &threadID,
	); err != nil {
		return nil, err
	}
	version, err := byteSliceFromValue(versionValue)
	if err != nil {
		return nil, err
	}
	if version == nil {
		version = []byte{0, 0, 0, 0, 0, 0}
	}
	packet := &tds.PreLoginPacket{
		Version:    version,
		Encryption: uint8(encryption),
		Instance:   instance,
		ThreadID:   uint32(threadID),
	}
	return &byteBuffer{data: packet.Marshal()}, nil
}

func parseTDSPrelogin(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := oneBytesArg(builtin.Name(), args, kwargs)
	if err != nil {
		return nil, err
	}
	packet, err := tds.ParsePreLoginResponse(data)
	if err != nil {
		return nil, err
	}
	return &scriptObject{typeName: "windows.tds.prelogin", fields: starlark.StringDict{
		"version":    &byteBuffer{data: packet.Version},
		"encryption": starlark.MakeInt(int(packet.Encryption)),
		"instance":   starlark.String(packet.Instance),
		"thread_id":  starlark.MakeUint64(uint64(packet.ThreadID)),
	}}, nil
}

func oneBytesArg(name string, args starlark.Tuple, kwargs []starlark.Tuple) ([]byte, error) {
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(name, args, kwargs, 1, &value); err != nil {
		return nil, err
	}
	data, err := byteSliceFromValue(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}
