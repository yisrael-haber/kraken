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

export function createScriptEditor(script = null) {
    return {
        name: script?.name || '',
        source: script?.source || DEFAULT_TRANSPORT_SCRIPT_SOURCE,
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
        updatedAt: script?.updatedAt || '',
    };
}
