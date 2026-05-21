export const SCRIPT_SURFACE_TRANSPORT = 'transport';
export const SCRIPT_SURFACE_APPLICATION = 'application';

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
#   packet.fixLengths
#   packet.computeChecksums
#   packet.layers
#   packet.layer(name)
#
# Context:
#   ctx.scriptName
#   ctx.adopted.*
#   ctx.metadata
#
# Builtins:
#   load("kraken/bytes", "bytes")
#   load("kraken/fragmentor", "fragmentor")
#   load("kraken/log", "log")
#   load("kraken/time", "time")
#   load("json", "json")
#   load("struct", "struct")
#   bytes.fromASCII(text)
#   bytes.fromUTF8(text)
#   bytes.fromHex("deadbeef")
#   bytes.concat(a, b, ...)
#   bytes.toHex(buf)
#   fragmentor.fragment(packet, maxPayloadSize)
#   fragmentor.dispatch(packet)
#   log.info(text) / log.warn(text) / log.error(text)
#   time.nowMs() / time.sleep(ms)
#   json.encode(x) / json.decode(text)
#   struct(...)

load("kraken/bytes", "bytes")
load("kraken/fragmentor", "fragmentor")

def main(packet, ctx):
    if packet.ipv4 != None and packet.ipv4.ttl > 1:
        packet.ipv4.ttl -= 1

    if packet.tcp != None:
        packet.tcp.window = 8192

    if len(packet.payload) == 0:
        packet.payload = bytes.fromASCII("kraken")
`;

const DEFAULT_APPLICATION_SCRIPT_SOURCE = `# Application script template
#
# Runs on engine-backed net.Conn buffers, not on packets.
# Kraken applies this script at the netruntime socket boundary on each buffer
# read from or written to that connection.
#
# This means:
#   - transport scripts = outbound packet hook
#   - application scripts = engine-backed socket buffer hook
#
# The first argument is a mutable buffer object:
#   buffer.direction
#       "inbound"  -> bytes read from the connection before the service handles them
#       "outbound" -> bytes written by the service before they go back into the stack
#
#   buffer.payload
#       Mutable byte buffer for the current read/write operation.
#
#   buffer.layers
#       Names of decoded application layers detected from the port mapping.
#
#   buffer.layer(name)
#       Returns the named mutable layer or None.
#
# Supported application layers in the current gopacket version:
#   buffer.dns
#   buffer.tls
#   buffer.modbusTCP
#
# Detection:
#   - Kraken uses gopacket's TCP/UDP port -> layer mapping.
#   - If the buffer does not match a known application layer, you still get
#     buffer.payload, but no decoded layer object.
#
# Mutation:
#   - Layer objects are mutable.
#   - Mutating a layer rebuilds buffer.payload when the script returns.
#   - Directly replacing buffer.payload bypasses layer rebuilding.
#   - Rebuilt DNS/TLS buffers preserve the framing values Kraken decoded from the
#     original bytes, such as DNS-over-TCP length prefixes, DNS section counts,
#     DNS record lengths, and TLS record lengths.
#
# Context:
#   ctx.scriptName
#   ctx.adopted.label
#   ctx.adopted.ip
#   ctx.adopted.mac
#   ctx.adopted.interfaceName
#   ctx.adopted.defaultGateway
#   ctx.adopted.mtu
#
#   ctx.connection.localAddress
#   ctx.connection.remoteAddress
#   ctx.connection.transport
#   ctx.metadata
#       Reserved for future use. Usually None.
#
# Important semantics:
#   - This is per read/write buffer, not per request/session.
#   - A large TLS stream may arrive in multiple buffers.
#   - Decoding depends on the port mapping, not the service name.
#   - Socket traffic can still hit a transport script after this hook.
#   - HTTPS hooks run before TLS termination, so buffer.payload contains TLS bytes.
#   - Plain HTTP has no decoded layer object yet; use buffer.payload.
#
# Useful helpers:
#   load("kraken/bytes", "bytes")
#   load("kraken/log", "log")
#   load("kraken/time", "time")
#   load("json", "json")
#   load("struct", "struct")
#   bytes.fromASCII(text)
#   bytes.fromUTF8(text)
#   bytes.fromHex("deadbeef")
#   bytes.concat(a, b, ...)
#   bytes.toHex(buf)
#   log.info(text) / log.warn(text) / log.error(text)
#   time.nowMs() / time.sleep(ms)
#   json.encode(x) / json.decode(text)
#   struct(...)
#
# Example patterns:
#   - Rewrite a DNS question name.
#   - Replace TLS application data record bytes.
#   - Adjust a ModbusTCP transaction identifier.

load("kraken/log", "log")

def main(buffer, ctx):
    dns = buffer.layer("dns")
    if dns != None and len(dns.questions) > 0:
        dns.questions[0].name = "example.org"

    tls = buffer.layer("tls")
    if tls != None and len(tls.records) > 0:
        log.info("tls %s records=%d" % (buffer.direction, len(tls.records)))

    modbus = buffer.layer("modbusTCP")
    if modbus != None:
        modbus.transactionIdentifier = modbus.transactionIdentifier + 1
`;

export function createScriptEditor(script = null, surface = SCRIPT_SURFACE_TRANSPORT) {
    const selectedSurface = script?.surface || surface || SCRIPT_SURFACE_TRANSPORT;
    const defaultSource = selectedSurface === SCRIPT_SURFACE_APPLICATION
        ? DEFAULT_APPLICATION_SCRIPT_SOURCE
        : DEFAULT_TRANSPORT_SCRIPT_SOURCE;

    return {
        name: script?.name || '',
        surface: selectedSurface,
        source: script?.source || defaultSource,
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
        updatedAt: script?.updatedAt || '',
    };
}
