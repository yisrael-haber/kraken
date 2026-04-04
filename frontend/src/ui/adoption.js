import {
    escapeHTML,
    pill,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
    renderStateLayout,
} from './common';

const ADOPTED_TABS = [
    ['info', 'Info'],
    ['arp', 'ARP'],
    ['icmp', 'ICMP'],
];

const ADOPT_MODES = [
    ['raw', 'Raw adoption'],
    ['stored', 'Stored configuration'],
];

function renderIdentityFields({disabled, fieldAttribute, form, interfaceOptions, interfaceNote, ipPlaceholder = '', macNote, macPlaceholder = ''}) {
    const ipPlaceholderAttr = ipPlaceholder ? ` placeholder="${ipPlaceholder}"` : '';
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
            />
            <small class="field-note">Used as the adopted tag and the stored configuration filename.</small>
        </label>

        <label class="form-field">
            <span>IP address</span>
            <input
                type="text"
                name="ip"
                value="${escapeHTML(form.ip)}"${ipPlaceholderAttr}
                autocomplete="off"
                spellcheck="false"
                ${fieldAttribute}="ip"
            />
        </label>

        <label class="form-field">
            <span>MAC address</span>
            <input
                type="text"
                name="mac"
                value="${escapeHTML(form.mac)}"${macPlaceholderAttr}
                autocomplete="off"
                spellcheck="false"
                ${fieldAttribute}="mac"
            />
            <small class="field-note">${macNote}</small>
        </label>

        <label class="form-field">
            <span>Network interface</span>
            <select
                name="interfaceName"
                ${disabled ? 'disabled' : ''}
                ${fieldAttribute}="interfaceName"
            >
                ${interfaceOptions}
            </select>
            <small class="field-note">${interfaceNote}</small>
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

function renderActivityTable(title, eyebrow, columns, rows, emptyText) {
    return `
        <section class="panel section-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">${escapeHTML(eyebrow)}</span>
                    <h3>${escapeHTML(title)}</h3>
                </div>
            </div>

            ${rows.length ? `
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
            ` : `<div class="empty-state">${escapeHTML(emptyText)}</div>`}
        </section>
    `;
}

function renderActivityControls(scope, details, state) {
    const busy = state.adoptedDetailsLoading || state.clearingAdoptedActivity;
    const isPending = state.pendingClearAdoptedActivity === scope;
    const eventCount = scope === 'arp'
        ? details?.arpEvents?.length ?? 0
        : details?.icmpEvents?.length ?? 0;
    const refreshLabel = state.adoptedDetailsLoading ? 'Refreshing...' : 'Refresh';
    const clearLabel = state.clearingAdoptedActivity ? 'Clearing...' : 'Clear logs';

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

function renderStoredConfigList(state) {
    if (state.storedConfigsLoading && !state.storedConfigs.length) {
        return '<div class="empty-state">Loading stored configurations...</div>';
    }
    if (state.storedConfigsError) {
        return renderMessageBanner('Stored configuration notice', state.storedConfigsError);
    }
    if (!state.storedConfigs.length) {
        return '<div class="empty-state">No stored configurations are available yet.</div>';
    }

    return `
        <div class="config-card-list">
            ${state.storedConfigs.map((item) => `
                <article class="panel config-card">
                    <div class="config-card__header">
                        <div>
                            <span class="eyebrow">Stored Configuration</span>
                            <h3>${escapeHTML(item.label)}</h3>
                        </div>
                        ${pill('Ready', 'info')}
                    </div>

                    <dl class="meta-list">
                        <div class="meta-list__row">
                            <dt>Interface</dt>
                            <dd>${escapeHTML(item.interfaceName)}</dd>
                        </div>
                        <div class="meta-list__row">
                            <dt>IP</dt>
                            <dd><code>${escapeHTML(item.ip)}</code></dd>
                        </div>
                        <div class="meta-list__row">
                            <dt>MAC</dt>
                            <dd><code>${escapeHTML(item.mac || 'Interface default')}</code></dd>
                        </div>
                    </dl>

                    <div class="section-actions">
                        <button
                            class="primary-button"
                            type="button"
                            data-adopt-stored-config="${escapeHTML(item.label)}"
                            ${state.adoptingStoredLabel ? 'disabled' : ''}
                        >
                            ${state.adoptingStoredLabel === item.label ? 'Adopting...' : 'Adopt configuration'}
                        </button>
                    </div>
                </article>
            `).join('')}
        </div>
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

    return renderActivityTable(
        'ARP activity',
        'Activity',
        ['Time', 'Direction', 'Event', 'Peer IP', 'Peer MAC', 'Details'],
        rows,
        state.adoptedDetailsLoading ? 'Loading ARP activity...' : 'No ARP events have been recorded for this adopted IP yet.',
    );
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

    return renderActivityTable(
        'ICMP activity',
        'Activity',
        ['Time', 'Direction', 'Event', 'Peer IP', 'ID/Seq', 'RTT', 'Status'],
        rows,
        state.adoptedDetailsLoading ? 'Loading ICMP activity...' : 'No ICMP events have been recorded for this adopted IP yet.',
    );
}

function renderInfoTab({details, hasStoredConfig, interfaces, item, state}) {
    const current = details ?? item;
    const busy = state.updatingAdoption || state.deletingAdoption || state.storingAdoptionConfig;
    const interfaceOptions = renderInterfaceOptions(interfaces, state.adoptedEditForm.interfaceName, 'No adoptable interfaces available');
    const deleteControl = state.pendingDeleteAdoption === item.ip
        ? `
            <div class="inline-danger-confirm">
                <span class="inline-confirm">Delete this adoption?</span>
                <button class="danger-button" type="button" data-confirm-delete-adoption="${escapeHTML(item.ip)}" ${busy ? 'disabled' : ''}>
                    ${state.deletingAdoption ? 'Deleting...' : 'Confirm delete'}
                </button>
                <button class="ghost-button" type="button" data-cancel-delete-adoption ${busy ? 'disabled' : ''}>
                    Cancel
                </button>
            </div>
        `
        : `
            <button class="danger-button" type="button" data-stage-delete-adoption="${escapeHTML(item.ip)}" ${busy ? 'disabled' : ''}>
                Delete adoption
            </button>
        `;

    return `
        <section class="panel section-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">Adopted IP</span>
                    <h3>${escapeHTML(current.label || current.ip)}</h3>
                </div>
                ${pill('Active', 'success')}
            </div>

            <dl class="meta-list">
                <div class="meta-list__row">
                    <dt>Label</dt>
                    <dd>${escapeHTML(current.label)}</dd>
                </div>
                <div class="meta-list__row">
                    <dt>IP</dt>
                    <dd><code>${escapeHTML(current.ip)}</code></dd>
                </div>
                <div class="meta-list__row">
                    <dt>Interface</dt>
                    <dd>${escapeHTML(current.interfaceName)}</dd>
                </div>
                <div class="meta-list__row">
                    <dt>MAC</dt>
                    <dd><code>${escapeHTML(current.mac)}</code></dd>
                </div>
            </dl>
        </section>

        <section class="panel section-panel form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">Configuration</span>
                    <h3>Edit adoption</h3>
                </div>
            </div>

            <form id="adopted-ip-edit-form" class="form-stack">
                ${renderIdentityFields({
                    disabled: busy || !interfaces.length,
                    fieldAttribute: 'data-adopted-edit-field',
                    form: state.adoptedEditForm,
                    interfaceOptions,
                    interfaceNote: 'Only interfaces approved by the backend for adoption are offered here.',
                    macNote: 'Set the advertised MAC for this adopted identity.',
                })}

                <div class="form-actions">
                    <button class="primary-button" type="submit" ${busy || !interfaces.length ? 'disabled' : ''}>
                        ${state.updatingAdoption ? 'Saving...' : 'Save changes'}
                    </button>
                    <button class="ghost-button" type="button" data-reset-adopted-edit ${busy ? 'disabled' : ''}>Reset</button>
                    <button class="ghost-button" type="button" data-store-adoption-config ${busy ? 'disabled' : ''}>
                        ${state.storingAdoptionConfig ? 'Storing...' : (hasStoredConfig ? 'Update configuration' : 'Save configuration')}
                    </button>
                    ${deleteControl}
                </div>
            </form>
        </section>
    `;
}

export function renderAdoptIPAddressForm({interfaces, state}) {
    if (state.interfacesLoading && !state.snapshot && state.adoptMode === 'raw') {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('Adopt IP', 'Choose a raw identity or reuse a stored configuration.')}
                ${renderStateLayout('single-panel-layout', 'Loading interfaces', 'Collecting interfaces.')}
            </div>
        `;
    }

    const rawDisabled = state.adopting || !interfaces.length;
    const interfaceOptions = renderInterfaceOptions(interfaces, state.adoptForm.interfaceName, 'No adoptable interfaces available');
    const modeTabs = renderButtonTabs(ADOPT_MODES, state.adoptMode, 'data-adopt-mode', 'Adoption modes');

    const body = state.adoptMode === 'stored'
        ? renderStoredConfigList(state)
        : `
            <section class="panel section-panel form-panel">
                <div class="section-heading section-heading--tight">
                    <div>
                        <span class="eyebrow">Raw Adoption</span>
                        <h3>Identity</h3>
                    </div>
                </div>

                <form id="adopt-ip-form" class="form-stack">
                    ${renderIdentityFields({
                        disabled: rawDisabled,
                        fieldAttribute: 'data-adopt-field',
                        form: state.adoptForm,
                        interfaceOptions,
                        interfaceNote: 'Only interfaces approved by the backend for adoption are shown here.',
                        ipPlaceholder: '192.168.56.50',
                        macNote: 'Leave empty to reuse the selected interface MAC.',
                        macPlaceholder: 'Optional',
                    })}

                    <div class="form-actions">
                        <button class="primary-button" type="submit" ${rawDisabled ? 'disabled' : ''}>
                            ${state.adopting ? 'Adopting...' : 'Adopt IP'}
                        </button>
                        <button class="ghost-button" type="button" data-go-home>Cancel</button>
                    </div>
                </form>
            </section>
        `;

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Adopt IP', 'Choose a raw identity or reuse a stored configuration.')}

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

export function renderAdoptedIPAddressView({details, hasStoredConfig, interfaces, item, state}) {
    if (!item) {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('Adopted IP', 'Open an adopted IP card from the home screen.')}
                ${renderStateLayout('single-panel-layout', 'No adopted IP selected', 'Return to the home screen and choose an adopted address.')}
            </div>
        `;
    }

    const current = details ?? item;
    let tabContent = renderInfoTab({details, hasStoredConfig, interfaces, item, state});

    if (state.selectedAdoptedTab === 'arp') {
        tabContent = `
            ${renderActivityControls('arp', details, state)}
            ${renderARPTable(details, state)}
        `;
    } else if (state.selectedAdoptedTab === 'icmp') {
        tabContent = `
            ${renderActivityControls('icmp', details, state)}
            ${renderICMPTable(details, state)}
        `;
    }

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar(current.label || current.ip, `${current.ip} on ${current.interfaceName}`)}
            <main class="single-panel-layout">
                ${state.adoptedUpdateError ? renderMessageBanner('Update failed', state.adoptedUpdateError) : ''}
                ${state.adoptionConfigError ? renderMessageBanner('Configuration notice', state.adoptionConfigError) : ''}
                ${state.adoptionConfigNotice ? renderMessageBanner('Configuration stored', state.adoptionConfigNotice) : ''}
                ${state.adoptedDetailsError ? renderMessageBanner('Activity notice', state.adoptedDetailsError) : ''}
                ${renderButtonTabs(ADOPTED_TABS, state.selectedAdoptedTab, 'data-adopted-tab', 'Adopted IP sections')}
                ${tabContent}
            </main>
        </div>
    `;
}
