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
#       "keepalive": True,      # bool
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
#   bytes.from_utf8(text)
#   bytes.concat(a, b, ...)
#   time.nowMs()
#   time.sleep(ms)  # cancelable by Stop
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
        updatedAt: script?.updatedAt || '',
    };
}
