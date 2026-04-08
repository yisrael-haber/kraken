import {
    escapeHTML,
    pill,
    renderCompactMetaLine,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
    renderStateLayout,
} from './common';
import {renderStoredConfigList} from './storedConfigCards';

const ADOPTED_TABS = [
    ['info', 'Identity'],
    ['arp', 'ARP'],
    ['icmp', 'ICMP'],
];

const ADOPT_MODES = [
    ['stored', 'Stored'],
    ['raw', 'Raw'],
];

function renderFieldNote(text) {
    if (!text) {
        return '<small class="field-note field-note--placeholder" aria-hidden="true">&nbsp;</small>';
    }

    return `<small class="field-note">${escapeHTML(text)}</small>`;
}

function renderIdentityFields({
    disabled,
    fieldAttribute,
    form,
    interfaceOptions,
    labelNote = '',
    interfaceNote = '',
    ipNote = '',
    ipPlaceholder = '',
    gatewayNote = '',
    gatewayPlaceholder = '',
    macNote = '',
    macPlaceholder = '',
}) {
    const ipPlaceholderAttr = ipPlaceholder ? ` placeholder="${ipPlaceholder}"` : '';
    const gatewayPlaceholderAttr = gatewayPlaceholder ? ` placeholder="${gatewayPlaceholder}"` : '';
    const macPlaceholderAttr = macPlaceholder ? ` placeholder="${macPlaceholder}"` : '';

    return `
        <label class="form-field">
            <span>Label</span>
            <input
                type="text"
                name="label"
                value="${escapeHTML(form.label)}"
                autocomplete="off"
                spellcheck="false"
                ${fieldAttribute}="label"
                ${disabled ? 'disabled' : ''}
            />
            ${renderFieldNote(labelNote)}
        </label>

        <label class="form-field">
            <span>IP</span>
            <input
                type="text"
                name="ip"
                value="${escapeHTML(form.ip)}"${ipPlaceholderAttr}
                autocomplete="off"
                spellcheck="false"
                ${fieldAttribute}="ip"
                ${disabled ? 'disabled' : ''}
            />
            ${renderFieldNote(ipNote)}
        </label>

        <label class="form-field">
            <span>Gateway</span>
            <input
                type="text"
                name="defaultGateway"
                value="${escapeHTML(form.defaultGateway || '')}"${gatewayPlaceholderAttr}
                autocomplete="off"
                spellcheck="false"
                ${fieldAttribute}="defaultGateway"
                ${disabled ? 'disabled' : ''}
            />
            ${renderFieldNote(gatewayNote)}
        </label>

        <label class="form-field">
            <span>MAC</span>
            <input
                type="text"
                name="mac"
                value="${escapeHTML(form.mac)}"${macPlaceholderAttr}
                autocomplete="off"
                spellcheck="false"
                ${fieldAttribute}="mac"
                ${disabled ? 'disabled' : ''}
            />
            ${renderFieldNote(macNote)}
        </label>

        <label class="form-field">
            <span>Interface</span>
            <select
                name="interfaceName"
                ${disabled ? 'disabled' : ''}
                ${fieldAttribute}="interfaceName"
            >
                ${interfaceOptions}
            </select>
            ${renderFieldNote(interfaceNote)}
        </label>
    `;
}

function renderButtonTabs(items, selectedValue, datasetKey, ariaLabel) {
    return `
        <nav class="tab-strip" aria-label="${escapeHTML(ariaLabel)}">
            ${items.map(([value, label]) => `
                <button
                    class="tab-button ${selectedValue === value ? 'is-active' : ''}"
                    type="button"
                    ${datasetKey}="${value}"
                    aria-pressed="${selectedValue === value ? 'true' : 'false'}"
                >
                    ${escapeHTML(label)}
                </button>
            `).join('')}
        </nav>
    `;
}

function renderInlineMeta(items, options = {}) {
    const denseClass = options.dense ? ' inline-meta--dense' : '';

    return `
        <div class="inline-meta${denseClass}">
            ${items.map((item) => `
                <div class="meta-chip">
                    <span>${escapeHTML(item.label)}</span>
                    ${item.code ? `<code>${escapeHTML(item.value)}</code>` : `<strong>${escapeHTML(item.value)}</strong>`}
                </div>
            `).join('')}
        </div>
    `;
}

function renderActivityTableContent(columns, rows, emptyText) {
    return rows.length ? `
        <div class="table-wrap">
            <table class="activity-table">
                <thead>
                    <tr>
                        ${columns.map((column) => `<th scope="col">${escapeHTML(column)}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${rows.join('')}
                </tbody>
            </table>
        </div>
    ` : `<div class="empty-state">${escapeHTML(emptyText)}</div>`;
}

function renderFoldPanel({title, eyebrow, summary, body, open = false}) {
    return `
        <details class="panel fold-panel" ${open ? 'open' : ''}>
            <summary class="fold-panel__summary">
                <div>
                    <span class="eyebrow">${escapeHTML(eyebrow)}</span>
                    <strong>${escapeHTML(title)}</strong>
                </div>
                ${summary ? `<span class="fold-panel__count">${escapeHTML(summary)}</span>` : ''}
            </summary>
            <div class="fold-panel__body">
                ${body}
            </div>
        </details>
    `;
}

function renderActivityControls(scope, details, state) {
    const busy = state.adoptedDetailsLoading || state.clearingAdoptedActivity;
    const isPending = state.pendingClearAdoptedActivity === scope;
    const eventCount = scope === 'arp'
        ? details?.arpEvents?.length ?? 0
        : details?.icmpEvents?.length ?? 0;
    const refreshLabel = state.adoptedDetailsLoading ? 'Refreshing...' : 'Refresh';
    const clearLabel = state.clearingAdoptedActivity ? 'Clearing...' : 'Clear';

    if (isPending) {
        return `
            <div class="section-actions section-actions--confirm">
                <span class="inline-confirm">Clear ${scope.toUpperCase()} logs?</span>
                <button class="danger-button" type="button" data-confirm-clear-adopted-activity="${scope}" ${busy ? 'disabled' : ''}>
                    ${clearLabel}
                </button>
                <button class="ghost-button" type="button" data-cancel-clear-adopted-activity ${busy ? 'disabled' : ''}>
                    Cancel
                </button>
            </div>
        `;
    }

    return `
        <div class="section-actions">
            <button class="ghost-button" type="button" data-refresh-adopted-details ${busy ? 'disabled' : ''}>
                ${refreshLabel}
            </button>
            <button class="danger-button" type="button" data-stage-clear-adopted-activity="${scope}" ${(busy || eventCount === 0) ? 'disabled' : ''}>
                ${clearLabel}
            </button>
        </div>
    `;
}

function renderOverrideBindingOptions(overrides, selectedName) {
    const items = ['<option value="">None</option>'];

    for (const item of overrides) {
        items.push(`
            <option value="${escapeHTML(item.name)}" ${item.name === selectedName ? 'selected' : ''}>
                ${escapeHTML(item.name)}
            </option>
        `);
    }

    return items.join('');
}

function renderOverrideBindingsPanel(title, eyebrow, fields, state) {
    const busy = state.savingAdoptedOverrideBindings || state.storedOverridesLoading || state.adoptedDetailsLoading;

    return `
        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">${escapeHTML(eyebrow)}</span>
                    <h3>${escapeHTML(title)}</h3>
                    <p>Choose stored overrides for this identity.</p>
                </div>
            </div>

            <form id="${escapeHTML(fields.formId)}" class="form-stack form-stack--compact">
                <div class="compact-form-grid compact-form-grid--two">
                    ${fields.items.map((field) => `
                        <label class="form-field">
                            <span>${escapeHTML(field.label)}</span>
                            <select
                                data-adopted-override-field="${escapeHTML(field.name)}"
                                ${busy ? 'disabled' : ''}
                            >
                                ${renderOverrideBindingOptions(state.storedOverrides, state.adoptedOverrideBindingsForm[field.name] || '')}
                            </select>
                            ${renderFieldNote(field.note)}
                        </label>
                    `).join('')}
                </div>

                <div class="form-actions form-actions--compact">
                    <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                        ${state.savingAdoptedOverrideBindings ? 'Saving...' : 'Save'}
                    </button>
                </div>
            </form>

            ${!state.storedOverridesLoading && !state.storedOverrides.length ? `
                <div class="empty-state">No stored overrides yet. Create one from Packet Overrides.</div>
            ` : ''}
        </section>
    `;
}

function renderARPTable(details, state) {
    const rows = (details?.arpEvents ?? []).map((event) => `
        <tr>
            <td><time datetime="${escapeHTML(event.timestamp || '')}">${escapeHTML(event.timestamp || '')}</time></td>
            <td>${escapeHTML(event.direction || '')}</td>
            <td>${escapeHTML(event.event || '')}</td>
            <td>${event.peerIP ? `<code>${escapeHTML(event.peerIP)}</code>` : '—'}</td>
            <td>${event.peerMAC ? `<code>${escapeHTML(event.peerMAC)}</code>` : '—'}</td>
            <td>${event.details ? escapeHTML(event.details) : '—'}</td>
        </tr>
    `);

    return renderActivityTableContent(
        ['Time', 'Dir', 'Event', 'Peer IP', 'Peer MAC', 'Details'],
        rows,
        state.adoptedDetailsLoading ? 'Loading ARP activity...' : 'No ARP events yet.',
    );
}

function renderARPCacheTable(details, state) {
    const rows = (details?.arpCacheEntries ?? []).map((entry) => `
        <tr>
            <td>${entry.ip ? `<code>${escapeHTML(entry.ip)}</code>` : '—'}</td>
            <td>${entry.mac ? `<code>${escapeHTML(entry.mac)}</code>` : '—'}</td>
            <td><time datetime="${escapeHTML(entry.updatedAt || '')}">${escapeHTML(entry.updatedAt || '')}</time></td>
        </tr>
    `);

    return renderActivityTableContent(
        ['IP', 'MAC', 'Updated'],
        rows,
        state.adoptedDetailsLoading ? 'Loading ARP cache...' : 'No ARP cache entries yet.',
    );
}

function renderPingResultTable(result) {
    const rows = (result?.replies ?? []).map((reply) => `
        <tr>
            <td>${escapeHTML(reply.sequence || 0)}</td>
            <td>${reply.success ? 'Success' : 'Timeout'}</td>
            <td>${reply.success ? `${escapeHTML(reply.rttMillis.toFixed(2))} ms` : '—'}</td>
        </tr>
    `);

    return renderActivityTableContent(
        ['Seq', 'Result', 'RTT'],
        rows,
        'No ping replies to show yet.',
    );
}

function renderICMPPingPanel(current, state) {
    const busy = state.pingingAdoptedIP;
    const result = state.pingResult;

    return `
        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">ICMP</span>
                    <h3>Ping</h3>
                    <p>Send from <code>${escapeHTML(current.ip)}</code>. Kraken resolves the next hop with ARP first.</p>
                </div>
            </div>

            <form id="adopted-ip-ping-form" class="ping-inline-form">
                <label class="form-field">
                    <span>Target</span>
                    <input
                        type="text"
                        name="targetIP"
                        value="${escapeHTML(state.pingForm.targetIP)}"
                        placeholder="192.168.56.1"
                        autocomplete="off"
                        spellcheck="false"
                        data-ping-field="targetIP"
                        ${busy ? 'disabled' : ''}
                    />
                </label>

                <label class="form-field ping-inline-form__count">
                    <span>Count</span>
                    <input
                        type="number"
                        name="count"
                        value="${escapeHTML(state.pingForm.count)}"
                        min="1"
                        step="1"
                        inputmode="numeric"
                        data-ping-field="count"
                        ${busy ? 'disabled' : ''}
                    />
                </label>

                <div class="form-actions form-actions--compact">
                    <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                        ${busy ? 'Pinging...' : 'Send'}
                    </button>
                </div>
            </form>

            ${result ? `
                ${renderInlineMeta([
        {label: 'Source', value: result.sourceIP, code: true},
        {label: 'Target', value: result.targetIP, code: true},
        {label: 'Sent', value: result.sent},
        {label: 'Recv', value: result.received},
    ], {dense: true})}
            ` : ''}
        </section>
    `;
}

function renderICMPTable(details, state) {
    const rows = (details?.icmpEvents ?? []).map((event) => {
        const idSequence = event.id || event.sequence
            ? `${escapeHTML(event.id || 0)}/${escapeHTML(event.sequence || 0)}`
            : '—';
        const rtt = event.rttMillis ? `${escapeHTML(event.rttMillis.toFixed(2))} ms` : '—';

        return `
            <tr>
                <td><time datetime="${escapeHTML(event.timestamp || '')}">${escapeHTML(event.timestamp || '')}</time></td>
                <td>${escapeHTML(event.direction || '')}</td>
                <td>${escapeHTML(event.event || '')}</td>
                <td>${event.peerIP ? `<code>${escapeHTML(event.peerIP)}</code>` : '—'}</td>
                <td>${idSequence}</td>
                <td>${rtt}</td>
                <td>${event.status ? escapeHTML(event.status) : '—'}</td>
            </tr>
        `;
    });

    return renderActivityTableContent(
        ['Time', 'Dir', 'Event', 'Peer IP', 'ID/Seq', 'RTT', 'Status'],
        rows,
        state.adoptedDetailsLoading ? 'Loading ICMP activity...' : 'No ICMP events yet.',
    );
}

function renderInfoTab({details, interfaces, item, state}) {
    const current = details ?? item;
    const busy = state.updatingAdoption;
    const interfaceOptions = renderInterfaceOptions(interfaces, state.adoptedEditForm.interfaceName, 'No adoptable interfaces available');

    return `
        <section class="panel section-panel section-panel--compact identity-summary">
            <div class="identity-summary__header">
                <div>
                    <span class="eyebrow">Active</span>
                    <h3>${escapeHTML(current.label || current.ip)}</h3>
                </div>
                ${pill('Active', 'success')}
            </div>

            ${renderInlineMeta([
        {label: 'IP', value: current.ip, code: true},
        ...(current.defaultGateway ? [{label: 'Gateway', value: current.defaultGateway, code: true}] : []),
        {label: 'MAC', value: current.mac, code: true},
        {label: 'Iface', value: current.interfaceName},
    ])}
        </section>

        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">Edit</span>
                    <h3>Identity</h3>
                    <p>Change this live identity.</p>
                </div>
            </div>

            <form id="adopted-ip-edit-form" class="form-stack form-stack--compact">
                <div class="compact-form-grid">
                    ${renderIdentityFields({
        disabled: busy || !interfaces.length,
        fieldAttribute: 'data-adopted-edit-field',
        form: state.adoptedEditForm,
        interfaceOptions,
        labelNote: 'Stored name.',
        ipNote: '',
        gatewayNote: 'Optional next hop for off-subnet traffic.',
        interfaceNote: 'Adoptable only.',
        gatewayPlaceholder: 'Optional',
        macNote: 'Keep current if blank.',
    })}
                </div>

                <div class="form-actions form-actions--compact">
                    <button class="primary-button" type="submit" ${busy || !interfaces.length ? 'disabled' : ''}>
                        ${state.updatingAdoption ? 'Saving...' : 'Save'}
                    </button>
                    <button class="ghost-button" type="button" data-reset-adopted-edit ${busy ? 'disabled' : ''}>Reset</button>
                </div>
            </form>
        </section>
    `;
}

export function renderAdoptIPAddressForm({interfaces, state}) {
    if (state.interfacesLoading && !state.snapshot && state.adoptMode === 'raw') {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('Adopt IP', 'Stored or raw identity.')}
                ${renderStateLayout('single-panel-layout', 'Loading interfaces', 'Collecting interfaces.')}
            </div>
        `;
    }

    const rawDisabled = state.adopting || !interfaces.length;
    const interfaceOptions = renderInterfaceOptions(interfaces, state.adoptForm.interfaceName, 'No adoptable interfaces available');
    const modeTabs = renderButtonTabs(ADOPT_MODES, state.adoptMode, 'data-adopt-mode', 'Adoption modes');

    const body = state.adoptMode === 'stored'
        ? `
            <section class="panel section-panel section-panel--compact">
                <div class="section-heading section-heading--tight">
                    <div>
                        <span class="eyebrow">Stored</span>
                        <h3>Configurations</h3>
                        <p>Reuse a saved identity. Manage them from Stored Adoptions.</p>
                    </div>
                </div>
                ${renderStoredConfigList(state, 'chooser')}
            </section>
        `
        : `
            <section class="panel section-panel section-panel--compact form-panel">
                <div class="section-heading section-heading--tight">
                    <div>
                        <span class="eyebrow">Raw</span>
                        <h3>New identity</h3>
                        <p>Fill only what Kraken needs.</p>
                    </div>
                </div>

                <form id="adopt-ip-form" class="form-stack form-stack--compact">
                    <div class="compact-form-grid">
                        ${renderIdentityFields({
        disabled: rawDisabled,
        fieldAttribute: 'data-adopt-field',
        form: state.adoptForm,
        interfaceOptions,
        labelNote: 'Stored name.',
        ipNote: '',
        gatewayNote: 'Optional next hop for off-subnet traffic.',
        interfaceNote: 'Adoptable only.',
        ipPlaceholder: '192.168.56.50',
        gatewayPlaceholder: 'Optional',
        macNote: 'Optional.',
        macPlaceholder: 'Optional',
    })}
                    </div>

                    <div class="form-actions form-actions--compact">
                        <button class="primary-button" type="submit" ${rawDisabled ? 'disabled' : ''}>
                            ${state.adopting ? 'Adopting...' : 'Adopt'}
                        </button>
                        <button class="ghost-button" type="button" data-go-home>Cancel</button>
                    </div>
                </form>
            </section>
        `;

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Adopt IP', 'Stored or raw identity.')}

            <main class="single-panel-layout">
                ${state.snapshot?.captureWarning ? renderMessageBanner('pcap notice', state.snapshot.captureWarning) : ''}
                ${state.interfaceError ? renderMessageBanner('Interface notice', state.interfaceError) : ''}
                ${state.adoptError ? renderMessageBanner('Adoption failed', state.adoptError) : ''}
                ${modeTabs}
                ${body}
            </main>
        </div>
    `;
}

export function renderAdoptedIPAddressView({details, interfaces, item, state}) {
    if (!item) {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('Adopted IP', 'Choose one from the home screen.')}
                ${renderStateLayout('single-panel-layout', 'No adopted IP selected', 'Return home and open an adopted identity.')}
            </div>
        `;
    }

    const current = details ?? item;

    let tabContent = renderInfoTab({details, interfaces, item, state});

    if (state.selectedAdoptedTab === 'arp') {
        const arpEvents = details?.arpEvents?.length ?? 0;
        const arpCacheEntries = details?.arpCacheEntries?.length ?? 0;

        tabContent = `
            ${renderOverrideBindingsPanel('ARP overrides', 'Overrides', {
        formId: 'adopted-arp-override-form',
        items: [
            {
                name: 'arpRequestOverride',
                label: 'Request',
                note: 'Used for outbound ARP requests.',
            },
            {
                name: 'arpReplyOverride',
                label: 'Reply',
                note: 'Used for outbound ARP replies.',
            },
        ],
    }, state)}
            ${renderFoldPanel({
        title: 'ARP cache',
        eyebrow: 'Kraken',
        summary: `${arpCacheEntries} ${arpCacheEntries === 1 ? 'entry' : 'entries'}`,
        body: renderARPCacheTable(details, state),
    })}
            ${renderFoldPanel({
        title: 'ARP activity',
        eyebrow: 'Logs',
        summary: `${arpEvents} ${arpEvents === 1 ? 'event' : 'events'}`,
        body: `
            ${renderActivityControls('arp', details, state)}
            ${renderARPTable(details, state)}
        `,
    })}
        `;
    } else if (state.selectedAdoptedTab === 'icmp') {
        const icmpEvents = details?.icmpEvents?.length ?? 0;
        const pingReplies = state.pingResult?.replies?.length ?? 0;

        tabContent = `
            ${renderOverrideBindingsPanel('ICMP overrides', 'Overrides', {
        formId: 'adopted-icmp-override-form',
        items: [
            {
                name: 'icmpEchoRequestOverride',
                label: 'Echo request',
                note: 'Used for pings sent from this identity.',
            },
            {
                name: 'icmpEchoReplyOverride',
                label: 'Echo reply',
                note: 'Used for automatic echo replies.',
            },
        ],
    }, state)}
            ${renderICMPPingPanel(current, state)}
            ${state.pingError ? renderMessageBanner('Ping failed', state.pingError) : ''}
            ${state.pingResult ? renderFoldPanel({
        title: 'Ping replies',
        eyebrow: 'ICMP',
        summary: `${pingReplies} ${pingReplies === 1 ? 'reply' : 'replies'}`,
        body: renderPingResultTable(state.pingResult),
        open: true,
    }) : ''}
            ${renderFoldPanel({
        title: 'ICMP activity',
        eyebrow: 'Logs',
        summary: `${icmpEvents} ${icmpEvents === 1 ? 'event' : 'events'}`,
        body: `
            ${renderActivityControls('icmp', details, state)}
            ${renderICMPTable(details, state)}
        `,
    })}
        `;
    }

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Adopted IP', 'Identity, activity, and overrides.')}
            <main class="single-panel-layout single-panel-layout--wide">
                ${state.adoptedUpdateError ? renderMessageBanner('Update failed', state.adoptedUpdateError) : ''}
                ${state.adoptedOverrideBindingsError ? renderMessageBanner('Override binding notice', state.adoptedOverrideBindingsError) : ''}
                ${state.adoptedDetailsError ? renderMessageBanner('Activity notice', state.adoptedDetailsError) : ''}
                ${renderButtonTabs(ADOPTED_TABS, state.selectedAdoptedTab, 'data-adopted-tab', 'Adopted IP sections')}
                ${tabContent}
            </main>
        </div>
    `;
}
