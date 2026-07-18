const DEFAULT_TRANSPORT_SCRIPT_SOURCE = `# Transport script template
#
# Runs on outbound packets after the gVisor netstack and before interface egress.
#
# Layers:
#   packet.ethernet  srcMAC, dstMAC, ethernetType, length
#   packet.arp       addrType, protocol, hwAddressSize, protAddressSize, operation
#                    sourceHwAddress, sourceProtAddress, dstHwAddress, dstProtAddress
#   packet.ipv4      srcIP, dstIP, version, ihl, tos, length, id, flags, fragOffset
#                    ttl, protocol, checksum, options, padding
#   packet.icmpv4    typeCode, type, code, checksum, id, seq
#   packet.tcp       srcPort, dstPort, seq, ack, dataOffset, flags, window, checksum
#                    urgentPointer, options
#   packet.udp       srcPort, dstPort, length, checksum
#
# Payload and helpers:
#   packet.payload
#   packet.copy()
#   packet.create_fragments(mtu)
#   packet.pad_payload(length, byte=0)
#   packet.send(fix_lengths=True, fix_checksums=True)
#   packet.truncate_payload(length)
#   packet.ipv4.options / packet.tcp.options -> [{type, length, data}, ...]
#   Binary values must be bytes: use b"\\x00\\xff", bytes.from_utf8(text),
#   or bytes.concat(...).
#   Packet numeric fields require integers. Packets drop by default.
#   send() fixes lengths/checksums unless explicitly disabled.
#
# Context:
#   ctx.scriptName
#   ctx.adopted.*
#   ctx.metadata
#
# Builtins:
#   load("kraken/bytes", "bytes")
#   load("kraken/time", "time")
#   bytes.from_utf8(text)
#   bytes.concat(a, b, ...)
#   b"\\x00\\xff" for binary byte literals
#   print(text)
#   time.nowMs() / time.sleep(ms)

load("kraken/bytes", "bytes")

def main(packet, ctx):
    if packet.ipv4 != None and packet.ipv4.ttl > 1:
        packet.ipv4.ttl -= 1

    if packet.tcp != None:
        packet.tcp.window = 8192

    if len(packet.payload) == 0:
        packet.payload = bytes.from_utf8("kraken")

    packet.send()
`;

const DEFAULT_GENERIC_SCRIPT_SOURCE = `# Generic script template
#
# Run manually from Global scripting -> Run.
# stdout/stderr stream live to the Run tab. Stop cancels the running script.
#
# Context:
#   ctx.scriptName
#   ctx.identities["10.0.0.1"]  adopted identity lookup by IP
#   ctx.metadata
#
# Identity fields:
#   identity.label
#   identity.ip
#   identity.mac
#   identity.interfaceName
#   identity.defaultGateway
#   identity.mtu
#
# Socket creation:
#   connection = socket.tcp(identity, "10.0.0.5:445")
#   connection = socket.udp(identity, "10.0.0.5:53")
#   Address must be "IPv4:port".
#
# Socket options:
#   options={
#       "ttl": 64,              # int, 0..255
#       "nodelay": True,        # bool, TCP delay off when True
#       "keepalive": True,      # bool, TCP only
#       "reuseaddr": True,      # bool
#       "recv_buffer": 262144,  # int bytes
#       "send_buffer": 262144,  # int bytes
#   }
# Unsupported options fail clearly.
#
# Connection API:
#   connection.send(b"bytes") -> bytes written
#   connection.recv(4096) -> bytes
#   connection.close()
#   connection.set_option("ttl", 32)
#   set_option accepts the same option names shown above.
#   connection.local_addr
#   connection.remote_addr
#
# Useful modules:
#   load("kraken/socket", "socket")
#   load("kraken/bytes", "bytes")
#   load("kraken/time", "time")
#   load("kraken/windows", "windows")
#   load("kraken/dcerpc", "dcerpc")
#   bytes.from_utf8(text)
#   bytes.concat(a, b, ...)
#   time.nowMs()
#   time.sleep(ms)  # cancelable by Stop
#
# Windows protocol helpers:
#   sid = windows.sid.parse("S-1-5-18")  # or parse binary SID bytes
#   sid.text / sid.bytes / sid.revision / sid.authority / sid.subAuthorities
#
#   sd = windows.security.parse_descriptor(bytes)
#   sd.revision / sd.control / sd.owner / sd.group / sd.sacl / sd.dacl / sd.bytes
#   acl = windows.security.parse_acl(bytes)
#   acl.revision / acl.aceCount / acl.aces / acl.bytes
#   ace = windows.security.parse_ace(bytes)
#   ace.type / ace.flags / ace.mask / ace.maskText / ace.sid / ace.text / ace.bytes / ace.consumed
#   windows.security.access_mask_text(0x001f01ff)
#
#   ntlm = windows.ntlm.client(user="alice", password="secret", domain="LAB",
#                              workstation="", hash="", target_spn="")
#   negotiate = ntlm.negotiate()
#   authenticate = ntlm.authenticate(challenge_bytes)
#
#   tds_prelogin = windows.tds.prelogin(encryption=0)
#   tds_packet = windows.tds.packet(type=windows.tds.type_prelogin,
#                                   data=tds_prelogin,
#                                   status=windows.tds.status_eom,
#                                   packet_id=1)
#   parsed_tds = windows.tds.parse_packet(tds_packet)
#   parsed_tds.type / parsed_tds.status / parsed_tds.length / parsed_tds.data
#   parsed_prelogin = windows.tds.parse_prelogin(tds_prelogin)
#   parsed_prelogin.version / parsed_prelogin.encryption / parsed_prelogin.instance
#
#   utf16 = windows.utf16le.encode("text")
#   text = windows.utf16le.decode(utf16)
#
# DCE/RPC helper:
#   epm = dcerpc.tcp(socket.tcp(identity, "10.0.0.5:135"))
#   endpoints = epm.epm_lookup()
#   endpoint = epm.epm_find(uuid="367ABB81-9844-35F1-AD32-98F038001003",
#                           major=None)
#   endpoint.uuid / endpoint.version / endpoint.major / endpoint.minor
#   endpoint.annotation / endpoint.protocol / endpoint.provider
#   endpoint.bindings / endpoint.tcp_bindings
#   binding = endpoint.tcp_binding()
#   binding.raw / binding.protocol / binding.host / binding.port / binding.address
#   epm.close()  # owns and closes the wrapped socket
#
#   rpc = dcerpc.tcp(socket.tcp(identity, binding.address))
#   rpc.bind(endpoint.uuid, major=endpoint.major, minor=endpoint.minor)
#   response = rpc.call(0, b"request")
#   rpc.close()
#
#   auth = windows.ntlm.client(user="alice", password="secret", domain="LAB")
#   rpc = dcerpc.tcp(socket.tcp(identity, binding.address))
#   rpc.bind_auth(endpoint.uuid, auth=auth, major=endpoint.major, minor=endpoint.minor)
#   response = rpc.call_auth(0, b"request")
#   rpc.close()
#
# DCE/RPC choices:
#   dcerpc.uuid("12345678-1234-5678-90ab-cdef01234567") -> wire UUID bytes
#   dcerpc.tcp(connection) requires an open TCP socket.connection.
#   dcerpc.tcp transfers socket ownership; close the RPC client.
#   DCE/RPC supports TCP bind/call, NTLM-auth TCP bind/call, and endpoint mapper.
#   Kerberos, SMB named pipes, high-level clients, and auto-dialing are not exposed.
#
# Example:
#   identity = ctx.identities["10.0.0.1"]
#   connection = socket.tcp(identity, "10.0.0.5:445", options={"nodelay": True})

load("kraken/socket", "socket")

def main(ctx):
    identity = ctx.identities["10.0.0.1"]
    connection = socket.tcp(identity, "10.0.0.5:80")
    connection.send(b"GET / HTTP/1.0\\r\\n\\r\\n")
    print(connection.recv(4096))
    connection.close()
`;

export const SCRIPT_KIND_TRANSPORT = 'transport';
export const SCRIPT_KIND_GENERIC = 'generic';

export function createScriptEditor(script = null, kind = SCRIPT_KIND_TRANSPORT) {
    return {
        name: script?.name || '',
        source: script?.source || (kind === SCRIPT_KIND_GENERIC ? DEFAULT_GENERIC_SCRIPT_SOURCE : DEFAULT_TRANSPORT_SCRIPT_SOURCE),
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
    };
}
