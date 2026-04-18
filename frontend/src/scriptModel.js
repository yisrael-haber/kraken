export const SCRIPT_SURFACE_PACKET = 'packet';
export const SCRIPT_SURFACE_HTTP_SERVICE = 'http_service';

const DEFAULT_PACKET_SCRIPT_SOURCE = `# Packet script template
#
# Transport surface.
# Runs on outbound packets for one adopted identity and routed packet egress.
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
#   packet.serialization.fixLengths
#   packet.serialization.computeChecksums
#   packet.layers
#   packet.layer(name)
#
# Context:
#   ctx.scriptName
#   ctx.adopted.label
#   ctx.adopted.ip
#   ctx.adopted.mac
#   ctx.adopted.interfaceName
#   ctx.adopted.defaultGateway
#   ctx.metadata
#
# Routed packets set ctx.metadata like:
#   ctx.metadata["stage"] == "routing"
#   ctx.metadata["route"]["label"]
#   ctx.metadata["route"]["destinationCIDR"]
#   ctx.metadata["route"]["viaAdoptedIP"]
#
# Builtins:
#   bytes.fromASCII(text)
#   bytes.fromUTF8(text)
#   bytes.fromHex("de ad be ef")
#   bytes.concat(a, b, ...)
#   bytes.toHex(buf)
#   log.info(text) / log.warn(text) / log.error(text)
#   time.nowMs() / time.sleep(ms)
#   json.encode(x) / json.decode(text)
#   struct(...)
#
# Notes:
#   - Missing layers are None.
#   - packet.payload is writable bytes.
#   - bytes are mutable: packet.payload[0] = 0x41
#   - packet.tcp.options is writable bytes and must stay 4-byte aligned.
#   - Leave packet.serialization.* enabled unless you need raw control.
#
# Example: routed TTL trim
#   if ctx.metadata != None and "stage" in ctx.metadata and ctx.metadata["stage"] == "routing":
#       if packet.ipv4 != None and packet.ipv4.ttl > 1:
#           packet.ipv4.ttl -= 1
#
# Example: TCP port redirect
#   if packet.tcp != None and packet.tcp.dstPort == 80:
#       packet.tcp.dstPort = 8080
#
# Example: UDP port redirect
#   if packet.udp != None and packet.udp.dstPort == 53:
#       packet.udp.dstPort = 5300
#
# Example: payload rewrite
#   if packet.icmpv4 != None and packet.icmpv4.type == 8:
#       packet.payload = bytes.fromASCII("kraken")

bytes = require("kraken/bytes")
log = require("kraken/log")

def main(packet, ctx):
    log.info("packet script %s on %s" % (ctx.scriptName, ctx.adopted.ip))

    if packet.ipv4 != None and packet.ipv4.ttl > 1:
        packet.ipv4.ttl -= 1

    if packet.tcp != None:
        packet.tcp.window = 8192

    if len(packet.payload) == 0:
        packet.payload = bytes.fromASCII("kraken")
`;

const DEFAULT_HTTP_SERVICE_SCRIPT_SOURCE = `# HTTP service script template
#
# Application surface: HTTP.
# Runs only on Kraken-managed HTTP or HTTPS services.
# HTTPS is decrypted before hooks and re-encrypted after them.
#
# Hooks:
#   def on_request(request, ctx):
#       return None
#       return struct(...)
#
#   def on_response(request, response, ctx):
#       return None
#       return struct(...)
#
# Request fields:
#   request.method
#   request.target
#   request.version
#   request.host
#   request.headers
#   request.body
#
# Response fields:
#   response.statusCode
#   response.reason
#   response.version
#   response.headers
#   response.body
#
# Context:
#   ctx.scriptName
#   ctx.adopted.label / ip / mac / interfaceName / defaultGateway
#   ctx.service.name / port / rootDirectory / useTLS
#   ctx.connection.remoteAddress
#   ctx.tls.enabled
#   ctx.tls.version
#   ctx.tls.cipherSuite
#   ctx.tls.serverName
#   ctx.tls.negotiatedProtocol
#   ctx.tls.peerCertificates
#   ctx.tls.localCertificate
#
# TLS certificate fields:
#   subject, issuer, serialNumber, dnsNames, ipAddresses, notBefore, notAfter
#
# Builtins:
#   bytes.fromASCII(text)
#   bytes.fromUTF8(text)
#   bytes.fromHex("de ad be ef")
#   log.info(text) / log.warn(text) / log.error(text)
#   time.nowMs() / time.sleep(ms)
#   json.encode(x) / json.decode(text)
#   struct(...)
#
# Notes:
#   - Mutate request or response in place, or return a replacement response.
#   - If you replace body bytes, update Content-Length yourself.
#   - TLS metadata is read-only.
#
# Example: block one path
#   if request.target == "/forbidden":
#       body = bytes.fromASCII("blocked")
#       return struct(
#           statusCode = 403,
#           headers = [
#               struct(name = "Content-Type", value = "text/plain"),
#               struct(name = "Content-Length", value = str(len(body))),
#           ],
#           body = body,
#       )
#
# Example: force a response header
#   response.headers.append(struct(name = "X-Kraken", value = "1"))
#
# Example: replace the response
#   body = bytes.fromASCII("ok")
#   return struct(
#       statusCode = 200,
#       headers = [
#           struct(name = "Content-Type", value = "text/plain"),
#           struct(name = "Content-Length", value = str(len(body))),
#       ],
#       body = body,
#   )

bytes = require("kraken/bytes")

def on_request(request, ctx):
    if ctx.tls.enabled:
        pass

    if request.target == "/forbidden":
        body = bytes.fromASCII("blocked")
        return struct(
            statusCode = 403,
            headers = [
                struct(name = "Content-Type", value = "text/plain"),
                struct(name = "Content-Length", value = str(len(body))),
            ],
            body = body,
        )

def on_response(request, response, ctx):
    response.headers = [
        struct(name = "Content-Type", value = "text/plain"),
        struct(name = "Content-Length", value = "2"),
    ]
    response.body = bytes.fromASCII("ok")
`;

export function createScriptEditor(script = null, surface = SCRIPT_SURFACE_PACKET) {
    const selectedSurface = script?.surface || surface || SCRIPT_SURFACE_PACKET;
    const defaultSource = selectedSurface === SCRIPT_SURFACE_HTTP_SERVICE
        ? DEFAULT_HTTP_SERVICE_SCRIPT_SOURCE
        : DEFAULT_PACKET_SCRIPT_SOURCE;

    return {
        name: script?.name || '',
        surface: selectedSurface,
        source: script?.source || defaultSource,
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
        updatedAt: script?.updatedAt || '',
    };
}
