export const SCRIPT_SURFACE_PACKET = 'packet';
export const SCRIPT_SURFACE_HTTP_SERVICE = 'http_service';
export const SCRIPT_SURFACE_TLS_SERVICE = 'tls_service';
export const SCRIPT_SURFACE_SSH_SERVICE = 'ssh_service';

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
#   ctx.adopted.mtu
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
#   fragmentor.fragment(packet, maxPayloadSize)
#   fragmentor.dispatch(packet)
#   log.info(text) / log.warn(text) / log.error(text)
#   time.nowMs() / time.sleep(ms)
#   json.encode(x) / json.decode(text)
#   struct(...)
#
# Notes:
#   - Missing layers are None.
#   - packet.payload is writable bytes.
#   - bytes are mutable: packet.payload[0] = 0x41
#   - packet.drop() suppresses the original frame after the script returns.
#   - fragmentor.fragment returns packet objects you may reorder and dispatch manually.
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
#
# Example: fragment, reorder, and suppress the original
#   frags = fragmentor.fragment(packet, 24)
#   if len(frags) > 1:
#       fragmentor.dispatch(frags[1])
#       fragmentor.dispatch(frags[0])
#       packet.drop()

bytes = require("kraken/bytes")
fragmentor = require("kraken/fragmentor")
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
# Runs only on plaintext Kraken-managed HTTP services.
# HTTPS does not use this surface.
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
#   ctx.adopted.mtu
#   ctx.service.name / port / rootDirectory / useTLS
#   ctx.connection.remoteAddress
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
#   - For HTTPS, use the TLS script surface instead.
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

const DEFAULT_TLS_SERVICE_SCRIPT_SOURCE = `# TLS service script template
#
# Application surface: TLS.
# Runs on raw TLS bytes for Kraken-managed HTTPS services.
# Payload is encrypted application data or handshake material.
#
# Fields:
#   stream.direction   "inbound" or "outbound"
#   stream.payload
#
# Context:
#   ctx.scriptName
#   ctx.adopted.label / ip / mac / interfaceName / defaultGateway
#   ctx.adopted.mtu
#   ctx.service.name / port / protocol / rootDirectory / useTLS
#   ctx.connection.localAddress
#   ctx.connection.remoteAddress
#   ctx.metadata
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
#   - This surface sees TLS records, not decrypted HTTP.
#   - You may change payload length.
#   - Invalid TLS changes will break the connection.
#
# Example: prepend a marker to outbound records
#   if stream.direction == "outbound" and len(stream.payload) > 0:
#       stream.payload = bytes.concat(bytes.fromHex("00"), stream.payload)

bytes = require("kraken/bytes")
log = require("kraken/log")

def main(stream, ctx):
    log.info("tls %s %d bytes" % (stream.direction, len(stream.payload)))
`;

const DEFAULT_SSH_SERVICE_SCRIPT_SOURCE = `# SSH service script template
#
# Application surface: SSH transport.
# Runs on raw SSH bytes for Kraken-managed SSH services.
# Payload may include cleartext version banners and encrypted SSH packets.
#
# Fields:
#   stream.direction   "inbound" or "outbound"
#   stream.payload
#
# Context:
#   ctx.scriptName
#   ctx.adopted.label / ip / mac / interfaceName / defaultGateway
#   ctx.adopted.mtu
#   ctx.service.name / port / protocol
#   ctx.connection.localAddress
#   ctx.connection.remoteAddress
#   ctx.metadata
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
#   - This surface sees SSH transport bytes, not parsed shell commands.
#   - You may change payload length.
#   - Invalid SSH changes will terminate the session.
#
# Example: log the cleartext banner exchange
#   if len(stream.payload) > 0:
#       log.info(bytes.toHex(stream.payload))

log = require("kraken/log")

def main(stream, ctx):
    log.info("ssh %s %d bytes" % (stream.direction, len(stream.payload)))
`;

export function createScriptEditor(script = null, surface = SCRIPT_SURFACE_PACKET) {
    const selectedSurface = script?.surface || surface || SCRIPT_SURFACE_PACKET;
    let defaultSource = DEFAULT_PACKET_SCRIPT_SOURCE;
    if (selectedSurface === SCRIPT_SURFACE_HTTP_SERVICE) {
        defaultSource = DEFAULT_HTTP_SERVICE_SCRIPT_SOURCE;
    } else if (selectedSurface === SCRIPT_SURFACE_TLS_SERVICE) {
        defaultSource = DEFAULT_TLS_SERVICE_SCRIPT_SOURCE;
    } else if (selectedSurface === SCRIPT_SURFACE_SSH_SERVICE) {
        defaultSource = DEFAULT_SSH_SERVICE_SCRIPT_SOURCE;
    }

    return {
        name: script?.name || '',
        surface: selectedSurface,
        source: script?.source || defaultSource,
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
        updatedAt: script?.updatedAt || '',
    };
}
