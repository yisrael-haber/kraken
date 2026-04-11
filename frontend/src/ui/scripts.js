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
        packet.ethernet.ethernetType = 2048
        packet.ethernet.length = 0

    if packet.ipv4 != None:
        packet.ipv4.srcIP = "192.168.1.10"
        packet.ipv4.dstIP = "192.168.1.1"
        packet.ipv4.version = 4
        packet.ipv4.ihl = 5
        packet.ipv4.length = 84
        packet.ipv4.flags = 2
        packet.ipv4.fragOffset = 0
        packet.ipv4.ttl = 64
        packet.ipv4.tos = 0
        packet.ipv4.id = 1337
        packet.ipv4.protocol = 1
        packet.ipv4.checksum = 0
        packet.ipv4.options = [
            struct(optionType=7, optionLength=4, optionData=bytes.fromHex("aa bb")),
        ]
        packet.ipv4.padding = bytes.fromHex("00 00")

    if packet.arp != None:
        packet.arp.addrType = 1
        packet.arp.protocol = 2048
        packet.arp.hwAddressSize = 6
        packet.arp.protAddressSize = 4
        packet.arp.operation = 1
        packet.arp.sourceHwAddress = "02:42:ac:11:00:02"
        packet.arp.sourceProtAddress = "192.168.1.10"
        packet.arp.dstHwAddress = "ff:ff:ff:ff:ff:ff"
        packet.arp.dstProtAddress = "192.168.1.1"

    if packet.icmpv4 != None:
        packet.icmpv4.typeCode = "EchoRequest"
        packet.icmpv4.type = 8
        packet.icmpv4.code = 0
        packet.icmpv4.checksum = 0
        packet.icmpv4.id = 1234
        packet.icmpv4.seq = 1

    packet.payload = bytes.fromHex("08 00 de ad")
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
time = require("kraken/time")
log = require("kraken/log")

def main(packet, ctx):
    log.info("editing %s" % ctx.scriptName)

    packet.payload = bytes.fromHex("DE AD BE EF")
    packet.payload = bytes.fromUTF8(ctx.scriptName)
    packet.payload = bytes.concat(
        bytes.fromASCII("PING:"),
        bytes.fromUTF8(ctx.scriptName),
        bytes.fromHex("00 ff"),
    )

    # load("json", "json")
    # load("struct", "struct")
    # time.sleep(100)`;

const SCRIPT_REFERENCE_NOTES = [
    'Layer objects can be None, so guard before reading or mutating nested fields.',
    'packet.payload is a mutable byte buffer. Use len(packet.payload), index assignment, slicing, or replace it with bytes.fromHex(...) and bytes.concat(...).',
    'bytes is available globally, and also via require("kraken/bytes"), for building payloads from hex strings, UTF-8 strings, or concatenated byte arrays.',
    'Set a layer to None to remove it from the packet before Kraken serializes it.',
    'packet.icmpv4.typeCode is a shorthand for named values or numeric pairs like 13/7. packet.icmpv4.type and packet.icmpv4.code give full control.',
    'packet.serialization.fixLengths = False and packet.serialization.computeChecksums = False preserve your manual length and checksum fields.',
    'ARP address fields accept normal MAC/IP text or raw hex bytes.',
    'Use struct(...) when you need to build nested values such as packet.ipv4.options entries.',
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
                                <small class="field-note">Entrypoint: <code>def main(packet, ctx):</code>. Built-ins: <code>bytes</code>, <code>log</code>, <code>time</code>, <code>struct</code>, and <code>load("json", "json")</code>.</small>
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
                    </section>
                </section>
            </main>
        </div>
    `;
}
