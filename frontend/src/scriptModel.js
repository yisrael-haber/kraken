const DEFAULT_SCRIPT_SOURCE = `function main(packet, ctx) {
    const time = require("kraken/time");
    const log = require("kraken/log");

    log.info("Editing " + ctx.sendPath + " for " + ctx.adopted.ip);

    if (packet.ipv4) {
        packet.ipv4.ttl = Math.max(1, packet.ipv4.ttl - 1);
    }

    if (packet.payload && packet.payload.length > 0) {
        packet.payload[0] = (packet.payload[0] + 1) & 0xff;
    }

    // time.sleep(100);
}
`;

export function createScriptEditor(script = null) {
    return {
        name: script?.name || '',
        source: script?.source || DEFAULT_SCRIPT_SOURCE,
        available: Boolean(script?.available),
        compileError: script?.compileError || '',
        updatedAt: script?.updatedAt || '',
        entryPoint: script?.entryPoint || 'main',
    };
}
