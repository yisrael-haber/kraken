const DEFAULT_SCRIPT_SOURCE = `# Kraken scripts use Starlark.
# Useful helpers:
#   bytes.fromASCII(text)
#   bytes.fromUTF8(text)
#   bytes.fromHex("de ad be ef")
#   bytes.concat(part1, part2, ...)
#   bytes.toHex(packet.payload)
#   http.parse(packet.payload)
#   http.build(message)
#   log.info(text) / log.warn(text) / log.error(text)
#   time.nowMs() / time.sleep(ms)
# Optional helpers:
#   load("json", "json")
#   load("struct", "struct")
#
# HTTP note:
#   See the Starlark Scripts view for the full HTTP guide.
#
# Common context:
#   ctx.scriptName
#   ctx.adopted.ip
#   ctx.adopted.mac
#   ctx.metadata

bytes = require("kraken/bytes")
http = require("kraken/http")
log = require("kraken/log")

def main(packet, ctx):
    log.info("editing %s for %s" % (ctx.scriptName, ctx.adopted.ip))

    # Layer objects can be None. Guard before mutating them.
    if packet.ipv4 != None and packet.ipv4.ttl > 1:
        packet.ipv4.ttl -= 1

    # packet.payload is a mutable byte buffer.
    if len(packet.payload) > 0:
        packet.payload[0] = (packet.payload[0] + 1) % 256
    else:
        packet.payload = bytes.concat(
            bytes.fromASCII("kraken:"),
            bytes.fromUTF8(ctx.scriptName),
        )

    # Other useful examples:
    # packet.payload = bytes.fromHex("de ad be ef")
    # packet.serialization.fixLengths = False
    # packet.serialization.computeChecksums = False
    # packet.icmpv4.typeCode = "13/7"
    # if packet.tcp != None:
    #     packet.tcp.dstPort = 8080
    #     packet.tcp.options = bytes.fromHex("01 01 01 01")
    #     packet.tcp.options[3] = 0x00
    #     packet.tcp.dataOffset = 24
    #     message = http.parse(packet.payload)
    #     message.headers = [
    #         struct(name="X-Kraken", value=ctx.scriptName),
    #     ]
    #     packet.payload = http.build(message)
`;

export function createScriptEditor(script = null) {
    return {
        name: script?.name || '',
        source: script?.source || DEFAULT_SCRIPT_SOURCE,
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
        updatedAt: script?.updatedAt || '',
    };
}
