import {
    escapeHTML,
    pill,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {
    SCRIPT_EDITOR_FONT_SIZE_OPTIONS,
    SCRIPT_EDITOR_FONT_SIZE_MAX,
    SCRIPT_EDITOR_FONT_SIZE_MIN,
    SCRIPT_EDITOR_THEME_OPTIONS,
} from '../scriptEditorOptions';

const SCRIPT_PACKET_REFERENCE = String.raw`bytes = require("kraken/bytes")

def main(packet, ctx):
    if packet.ethernet != None:
        packet.ethernet.srcMAC = "02:42:ac:11:00:02"
        packet.ethernet.dstMAC = "ff:ff:ff:ff:ff:ff"
        packet.ethernet.ethernetType = 0x0800

    if packet.ipv4 != None:
        packet.ipv4.srcIP = "192.168.1.10"
        packet.ipv4.dstIP = "192.168.1.1"
        packet.ipv4.ttl = 64
        packet.ipv4.tos = 0
        packet.ipv4.id = 1337
        packet.ipv4.protocol = 6

    if packet.tcp != None:
        packet.tcp.srcPort = 4444
        packet.tcp.dstPort = 8080
        packet.tcp.seq = packet.tcp.seq + 1
        packet.tcp.flags = 0x18
        packet.tcp.window = 8192
        packet.tcp.urgentPointer = 0
        packet.tcp.options = bytes.fromHex("01 01 01 01")
        packet.tcp.options[3] = 0x00
        packet.tcp.dataOffset = 24

    if packet.icmpv4 != None:
        packet.icmpv4.typeCode = "EchoReply"
        packet.icmpv4.id = 1234
        packet.icmpv4.seq = 1

    packet.payload = bytes.fromHex("de ad be ef")
    packet.serialization.fixLengths = True
    packet.serialization.computeChecksums = True`;

const SCRIPT_CONTEXT_REFERENCE = String.raw`ctx.scriptName         # "icmp-adjust"
ctx.adopted.label      # "lab-host"
ctx.adopted.ip         # "192.168.1.10"
ctx.adopted.mac        # "02:42:ac:11:00:02"
ctx.adopted.interfaceName
ctx.adopted.defaultGateway
ctx.metadata           # dict or None`;

const SCRIPT_MODULE_REFERENCE = String.raw`bytes = require("kraken/bytes")
http = require("kraken/http")
time = require("kraken/time")
log = require("kraken/log")

def main(packet, ctx):
    log.info("editing %s" % ctx.scriptName)

    if packet.tcp != None:
        message = http.parse(packet.payload)
        message.headers = [
            struct(name="Host", value="example.test"),
            struct(name="X-Kraken", value=ctx.scriptName),
            struct(name="Content-Length", value="2"),
        ]
        message.body = bytes.fromASCII("ok")
        packet.payload = http.build(message)

    # load("json", "json")
    # load("struct", "struct")
    # time.sleep(100)`;

const HTTP_TUTORIAL_PARSE_REFERENCE = String.raw`bytes = require("kraken/bytes")
http = require("kraken/http")
log = require("kraken/log")

def main(packet, ctx):
    if packet.tcp == None:
        return
    if len(packet.payload) == 0:
        return

    log.info("tcp %s -> %s payload=%s" % (
        packet.tcp.srcPort,
        packet.tcp.dstPort,
        len(packet.payload),
    ))
    log.info("payload hex: %s" % bytes.toHex(packet.payload))

    # Only call http.parse when this flow is expected to be HTTP.
    message = http.parse(packet.payload)
    log.info("http %s %s" % (message.kind, message.version))`;

const HTTP_TUTORIAL_REQUEST_REFERENCE = String.raw`bytes = require("kraken/bytes")
http = require("kraken/http")

def main(packet, ctx):
    if packet.tcp == None or len(packet.payload) == 0:
        return

    message = http.parse(packet.payload)
    if message.kind != "request":
        return

    packet.tcp.dstPort = 8080
    message.method = "POST"
    message.target = "/collect"
    message.headers = [
        struct(name="Host", value="lab.example"),
        struct(name="X-Kraken", value=ctx.scriptName),
        struct(name="Content-Length", value="4"),
    ]
    message.body = bytes.fromASCII("ping")
    packet.payload = http.build(message)`;

const HTTP_TUTORIAL_RESPONSE_REFERENCE = String.raw`bytes = require("kraken/bytes")
http = require("kraken/http")

def main(packet, ctx):
    if packet.tcp == None:
        return

    packet.payload = http.build(struct(
        kind="response",
        version="HTTP/1.1",
        statusCode=200,
        reason="OK",
        headers=[
            struct(name="Content-Type", value="text/plain"),
            struct(name="Content-Length", value="2"),
        ],
        body=bytes.fromASCII("ok"),
    ))`;

const HTTP_TUTORIAL_MENTAL_MODEL = [
    'HTTP is just TCP payload surgery here. Kraken does not infer HTTP from port 80, 8080, or anything else.',
    'http.parse(packet.payload) reads only the current payload bytes and returns a mutable message object with kind, version, request/response fields, headers, and body.',
    'http.build(message) writes a fresh payload from that object. It does not auto-fix Host, Content-Length, Transfer-Encoding, chunking, compression, or cookies.',
    'packet.serialization fixes packet lengths and checksums only. It does not repair HTTP semantics for you.',
];

const HTTP_TUTORIAL_FAILURES = [
    '<code>http.parse(...)</code> fails if the payload has no HTTP start line.',
    'Request lines must be <code>METHOD TARGET VERSION</code>.',
    'Response lines must start with <code>HTTP/...</code> and use a numeric status code.',
    'Each header line must contain <code>:</code>.',
    '<code>http.build(...)</code> request mode needs <code>method</code> and <code>target</code>.',
    '<code>http.build(...)</code> response mode needs <code>statusCode</code> between <code>0</code> and <code>999</code>.',
    '<code>message.headers</code> must be a dict, a list of <code>(name, value)</code> tuples, or a list of <code>struct(name=..., value=...)</code> objects.',
    'Kraken Starlark has no <code>try/except</code>. A parse/build failure aborts <code>main(packet, ctx)</code> immediately.',
];

const HTTP_TUTORIAL_DEBUG_FLOW = [
    'Start by logging TCP ports and payload length before you call <code>http.parse(...)</code>.',
    'Log <code>bytes.toHex(packet.payload)</code> so you can confirm you are actually looking at HTTP text and not TLS, gzip, chunked framing, or some unrelated protocol.',
    'Only after that should you parse and inspect <code>message.kind</code>, <code>message.method</code>, <code>message.target</code>, or <code>message.statusCode</code>.',
    'Whenever you replace <code>message.body</code>, update the HTTP headers yourself. The most common footgun is forgetting <code>Content-Length</code>.',
];

const SCRIPT_REFERENCE_NOTES = [
    'Layer objects can be None, so guard before reading or mutating nested fields.',
    'packet.payload is a mutable byte buffer. Use len(packet.payload), index assignment, slicing, or replace it with bytes.fromHex(...) and bytes.concat(...).',
    'bytes is available globally, and also via require("kraken/bytes"), for building payloads from hex strings, UTF-8 strings, or concatenated byte arrays.',
    'packet.icmpv4.typeCode is a shorthand for named values or numeric pairs like 13/7. packet.icmpv4.type and packet.icmpv4.code give full control.',
    'packet.tcp.options is a mutable byte buffer. Resize the TCP header with packet.tcp.dataOffset in 4-byte increments, or replace packet.tcp.options directly.',
    'require("kraken/http") gives you http.parse(packet.payload) and http.build(message). HTTP is treated as raw TCP payload, not inferred from the port.',
    'packet.serialization.fixLengths = False and packet.serialization.computeChecksums = False preserve your manual length and checksum fields.',
    'ARP address fields accept normal MAC/IP text or raw hex bytes.',
    'packet.ipv4.options and packet.ipv4.padding are inspect-only on the live mutable packet path. IPv4 option resizing is not supported there.',
    'The exposed packet surface is field-level edits on the existing frame plus payload replacement.',
];

function renderPreferenceOptions(items, selectedValue) {
    return items.map((item) => `
        <option value="${escapeHTML(item.value)}" ${item.value === selectedValue ? 'selected' : ''}>
            ${escapeHTML(item.label)}
        </option>
    `).join('');
}

function renderStoredScriptList(state) {
    if (state.storedScriptsLoading && !state.storedScripts.length) {
        return '<div class="empty-state">Loading stored scripts...</div>';
    }

    if (!state.storedScripts.length) {
        return '<div class="empty-state">No Starlark scripts yet.</div>';
    }

    return `
        <div class="config-card-list config-card-list--compact">
            ${state.storedScripts.map((item) => {
        const isSelected = state.selectedStoredScriptName === item.name;
        const isPendingDelete = state.pendingDeleteStoredScript === item.name;
        const busy = state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading;

        return `
                    <article class="panel compact-list-card override-card ${isSelected ? 'is-selected' : ''}">
                        <div class="compact-list-card__row">
                            <div>
                                <strong>${escapeHTML(item.name)}</strong>
                                <p>${escapeHTML(item.available ? 'Compiled and ready.' : item.compileError || 'Unavailable.')}</p>
                            </div>
                            ${item.available ? pill('Ready', 'success') : pill('Issue', 'warn')}
                        </div>

                        ${isPendingDelete ? `
                            <div class="section-actions section-actions--confirm">
                                <span class="inline-confirm">Delete this script?</span>
                                <button
                                    class="danger-button"
                                    type="button"
                                    data-confirm-delete-stored-script="${escapeHTML(item.name)}"
                                    ${state.deletingStoredScriptName ? 'disabled' : ''}
                                >
                                    ${state.deletingStoredScriptName === item.name ? 'Deleting...' : 'Delete'}
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-cancel-delete-stored-script
                                    ${state.deletingStoredScriptName ? 'disabled' : ''}
                                >
                                    Cancel
                                </button>
                            </div>
                        ` : `
                            <div class="section-actions">
                                <button
                                    class="primary-button"
                                    type="button"
                                    data-edit-stored-script="${escapeHTML(item.name)}"
                                    ${busy ? 'disabled' : ''}
                                >
                                    Edit
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-stage-delete-stored-script="${escapeHTML(item.name)}"
                                    ${busy ? 'disabled' : ''}
                                >
                                    Remove
                                </button>
                            </div>
                        `}
                    </article>
                `;
    }).join('')}
        </div>
    `;
}

function renderScriptReference() {
    return `
        <section class="script-reference">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">Reference</span>
                    <h3>Runtime packet surface</h3>
                    <p>This matches the Starlark values Kraken passes into <code>main(packet, ctx)</code>.</p>
                </div>
            </div>

            <div class="script-reference-grid">
                <article class="script-reference-card">
                    <strong>packet</strong>
                    <pre class="script-reference-code"><code>${escapeHTML(SCRIPT_PACKET_REFERENCE)}</code></pre>
                </article>

                <article class="script-reference-card">
                    <strong>ctx</strong>
                    <pre class="script-reference-code"><code>${escapeHTML(SCRIPT_CONTEXT_REFERENCE)}</code></pre>
                </article>

                <article class="script-reference-card">
                    <strong>modules</strong>
                    <pre class="script-reference-code"><code>${escapeHTML(SCRIPT_MODULE_REFERENCE)}</code></pre>
                </article>
            </div>

            <div class="script-reference-notes">
                ${SCRIPT_REFERENCE_NOTES.map((note) => `
                    <p class="script-reference-note">${escapeHTML(note)}</p>
                `).join('')}
            </div>
        </section>
    `;
}

function renderHTMLList(items, className) {
    return `
        <ul class="${className}">
            ${items.map((item) => `<li>${item}</li>`).join('')}
        </ul>
    `;
}

function renderHTTPScriptTutorial() {
    return `
        <section class="script-reference script-guide">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">Tutorial</span>
                    <h3>HTTP scripting</h3>
                    <p>This guide matches Kraken’s actual <code>kraken/http</code> behavior. It is intentionally literal because the module is literal.</p>
                </div>
            </div>

            <div class="script-reference-grid script-guide-grid">
                <article class="script-reference-card script-reference-card--wide">
                    <strong>Mental model</strong>
                    ${renderHTMLList(HTTP_TUTORIAL_MENTAL_MODEL, 'script-guide-list')}
                </article>

                <article class="script-reference-card">
                    <strong>1. Debug before parse</strong>
                    <p class="script-guide-caption">If HTTP work feels silent, start here. Prove you are actually holding HTTP bytes.</p>
                    <pre class="script-reference-code"><code>${escapeHTML(HTTP_TUTORIAL_PARSE_REFERENCE)}</code></pre>
                </article>

                <article class="script-reference-card">
                    <strong>2. Rewrite a request</strong>
                    <p class="script-guide-caption">Parse, verify <code>message.kind</code>, then rebuild the payload after you update headers and body.</p>
                    <pre class="script-reference-code"><code>${escapeHTML(HTTP_TUTORIAL_REQUEST_REFERENCE)}</code></pre>
                </article>

                <article class="script-reference-card">
                    <strong>3. Build a response from scratch</strong>
                    <p class="script-guide-caption">Use this when you want to replace the payload completely instead of mutating an existing message.</p>
                    <pre class="script-reference-code"><code>${escapeHTML(HTTP_TUTORIAL_RESPONSE_REFERENCE)}</code></pre>
                </article>

                <article class="script-reference-card">
                    <strong>4. What actually throws</strong>
                    ${renderHTMLList(HTTP_TUTORIAL_FAILURES, 'script-guide-list')}
                </article>

                <article class="script-reference-card script-reference-card--wide">
                    <strong>5. Debug flow</strong>
                    ${renderHTMLList(HTTP_TUTORIAL_DEBUG_FLOW, 'script-guide-list')}
                </article>
            </div>
        </section>
    `;
}

export function renderScriptsModule({state}) {
    const busy = state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading;
    const isEditing = Boolean(state.selectedStoredScriptName);
    const preferences = state.scriptEditorPreferences;

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Starlark Scripts', 'Filesystem-backed Starlark packet mutation scripts and the only dynamic modifier path.')}

            <main class="single-panel-layout single-panel-layout--wide script-workspace">
                ${state.storedScriptsError ? renderMessageBanner('Script notice', state.storedScriptsError) : ''}
                ${state.storedScriptNotice ? renderMessageBanner('Script update', state.storedScriptNotice) : ''}

                <section class="override-layout script-layout">
                    <section class="panel section-panel section-panel--compact">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Inventory</span>
                                <h3>Stored Starlark scripts</h3>
                                <p>Compiled from Kraken config scripts and bound per send path from the adopted identity view.</p>
                            </div>
                            <div class="section-actions">
                                <button class="ghost-button" type="button" data-refresh-stored-scripts ${busy ? 'disabled' : ''}>
                                    Refresh
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-script ${busy ? 'disabled' : ''}>
                                    New
                                </button>
                            </div>
                        </div>

                        ${renderStoredScriptList(state)}
                    </section>

                    <section class="panel section-panel section-panel--compact form-panel script-editor-panel">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Editor</span>
                                <h3>${isEditing ? escapeHTML(state.selectedStoredScriptName) : 'New script'}</h3>
                                <p>${isEditing ? 'Edit the source and save to recompile.' : 'Create a Starlark packet editing script with a def main(packet, ctx): entrypoint.'}</p>
                            </div>
                        </div>

                        <form id="stored-script-form" class="form-stack form-stack--compact">
                            <div class="script-editor-toolbar">
                                <label class="form-field script-editor-toolbar__name">
                                    <span>Name</span>
                                    <input
                                        type="text"
                                        name="name"
                                        value="${escapeHTML(state.scriptEditor.name)}"
                                        autocomplete="off"
                                        spellcheck="false"
                                        data-script-field="name"
                                        ${(busy || isEditing) ? 'disabled' : ''}
                                    />
                                    <small class="field-note">Filename and dropdown label.</small>
                                </label>

                                <div class="script-editor-toolbar__pair">
                                    <label class="form-field">
                                        <span>Theme</span>
                                        <select name="editorTheme" data-script-editor-preference="theme">
                                            ${renderPreferenceOptions(SCRIPT_EDITOR_THEME_OPTIONS, preferences.theme)}
                                        </select>
                                        <small class="field-note">Switch the dark editor palette.</small>
                                    </label>

                                    <label class="form-field">
                                        <span>Font Size</span>
                                        <select name="editorFontSize" data-script-editor-preference="fontSize">
                                            ${renderPreferenceOptions(SCRIPT_EDITOR_FONT_SIZE_OPTIONS, preferences.fontSize)}
                                        </select>
                                        <small class="field-note">Line numbers stay on. Range: ${SCRIPT_EDITOR_FONT_SIZE_MIN}-${SCRIPT_EDITOR_FONT_SIZE_MAX} px.</small>
                                    </label>
                                </div>
                            </div>

                            <label class="form-field">
                                <span>Source</span>
                                <div class="script-editor-shell">
                                    <div
                                        class="script-editor script-editor-prism"
                                        data-script-code-host
                                        role="textbox"
                                        aria-label="Starlark source editor"
                                    ></div>
                                </div>
                                <small class="field-note">Entrypoint: <code>def main(packet, ctx):</code>. Built-ins: <code>bytes</code>, <code>http</code>, <code>log</code>, <code>time</code>, <code>struct</code>, and <code>load("json", "json")</code>.</small>
                            </label>

                            ${state.scriptEditor.updatedAt ? `
                                <p class="field-note">Last compiled snapshot: ${escapeHTML(state.scriptEditor.updatedAt)}</p>
                            ` : ''}

                            <div class="form-actions form-actions--compact">
                                <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                                    ${state.savingStoredScript ? 'Saving...' : 'Save'}
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-script ${busy ? 'disabled' : ''}>
                                    Reset
                                </button>
                            </div>
                        </form>

                        ${renderScriptReference()}
                        ${renderHTTPScriptTutorial()}
                    </section>
                </section>
            </main>
        </div>
    `;
}
