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
#   Binary values must be bytes: use b"\\x00\\xff", bytes.from_utf8(text),
#   or bytes.concat(...).
#   Packet numeric fields require integers. Lengths and checksums are kept as
#   assigned; set them explicitly when you want them changed.
#   packet.recalculateLengths() / packet.recalculateChecksums()
#   packet.recalculateLengthsAndChecksums()
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
`;

const DEFAULT_APPLICATION_SCRIPT_SOURCE = `# Application script template
#
# Application scripts are compiled, stored, and bindable.
# Runtime application execution is currently disabled while this surface is
# being rebuilt.
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
#   ctx.metadata
#       Reserved for future use. Usually None.
#
# Useful helpers:
#   load("kraken/bytes", "bytes")
#   load("kraken/time", "time")
#   bytes.from_utf8(text)
#   bytes.concat(a, b, ...)
#   b"\\x00\\xff" for binary byte literals
#   Binary buffers do not accept plain text strings implicitly.
#   print(text)
#   time.nowMs() / time.sleep(ms)

def main(buffer, ctx):
    print("application script stored: %s" % ctx.scriptName)
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
