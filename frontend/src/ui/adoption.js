import {
    escapeHTML,
    pill,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
    renderStateLayout,
} from './common';
import {renderStoredConfigList} from './storedConfigCards';
import {
    SCRIPT_SURFACE_HTTP_SERVICE,
    SCRIPT_SURFACE_PACKET,
} from '../scriptModel';

const ADOPTED_TABS = [
    ['info', 'Info'],
    ['operations', 'Ops'],
    ['services', 'Services'],
];

const ADOPTED_SERVICE_TABS = [
    ['http', 'HTTP'],
    ['echo', 'Echo'],
];

const ADOPT_MODES = [
    ['stored', 'Saved'],
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

function renderFoldPanel({title, summary, body, open = false}) {
    return `
        <details class="panel fold-panel" ${open ? 'open' : ''}>
            <summary class="fold-panel__summary">
                <div>
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

function findStoredScript(storedScripts, name, surface = SCRIPT_SURFACE_PACKET) {
    return storedScripts.find((item) => item.name === name && item.surface === surface) || null;
}

function findTCPService(details, service) {
    return (details?.tcpServices || []).find((item) => item.service === service) || null;
}

export function renderScriptOptions(storedScripts, surface, selectedName) {
    const items = ['<option value="">None</option>'];
    const availableScripts = storedScripts.filter((item) => item.available && item.surface === surface);

    for (const script of availableScripts) {
        items.push(`
            <option value="${escapeHTML(script.name)}" ${script.name === selectedName ? 'selected' : ''}>
                ${escapeHTML(script.name)}
            </option>
        `);
    }

    if (selectedName) {
        const selectedScript = findStoredScript(storedScripts, selectedName, surface);
        if (!selectedScript || !selectedScript.available) {
            const suffix = selectedScript ? ' (Unavailable)' : ' (Missing)';
            items.push(`
                <option value="${escapeHTML(selectedName)}" selected>
                    ${escapeHTML(`${selectedName}${suffix}`)}
                </option>
            `);
        }
    }

    return items.join('');
}

function renderScriptStatus(storedScripts, selectedName) {
    if (!selectedName) {
        return '';
    }

    const selectedScript = findStoredScript(storedScripts, selectedName, SCRIPT_SURFACE_PACKET);
    if (!selectedScript) {
        return `Current script "${selectedName}" is missing from disk. Choose a replacement or None before saving.`;
    }
    if (!selectedScript.available) {
        return `Current script "${selectedName}" has a compile issue and cannot be reused until it is fixed.`;
    }

    return '';
}

export function renderSurfaceScriptStatus(storedScripts, selectedName, surface) {
    if (!selectedName) {
        return '';
    }

    const selectedScript = findStoredScript(storedScripts, selectedName, surface);
    if (!selectedScript) {
        return `Current script "${selectedName}" is missing from disk. Choose a replacement or None before saving.`;
    }
    if (!selectedScript.available) {
        return `Current script "${selectedName}" has a compile issue and cannot be reused until it is fixed.`;
    }

    return '';
}

function renderInfoScriptControl(state) {
    const busy = state.savingAdoptedScript || state.storedScriptsLoading || state.adoptedDetailsLoading;
    const selectedName = state.adoptedScriptName || '';
    const status = renderScriptStatus(state.storedScripts, selectedName);

    return `
        <form id="adopted-script-form" class="identity-summary__inline-form">
            <label class="form-field identity-summary__inline-field">
                <span>Use packet script</span>
                <select
                    data-adopted-script-name
                    ${busy ? 'disabled' : ''}
                >
                    ${renderScriptOptions(state.storedScripts, SCRIPT_SURFACE_PACKET, selectedName)}
                </select>
            </label>
            <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                ${state.savingAdoptedScript ? 'Saving...' : 'Save'}
            </button>
        </form>
        ${status ? `<p class="field-note">${escapeHTML(status)}</p>` : ''}
    `;
}

function renderInfoCaptureControl(current, state) {
    const recording = current.recording || null;
    const active = Boolean(recording?.active);
    const busy = state.startingAdoptedRecording || state.stoppingAdoptedRecording || state.adoptedDetailsLoading;

    return `
        <div class="identity-summary__capture">
            <div class="identity-summary__capture-action">
                ${active ? `
                    <button class="danger-button" type="button" data-stop-adopted-recording ${busy ? 'disabled' : ''}>
                        ${state.stoppingAdoptedRecording ? 'Stopping...' : 'Stop Capture on Adopted IP'}
                    </button>
                ` : `
                    <button class="primary-button" type="button" data-start-adopted-recording ${busy ? 'disabled' : ''}>
                        ${state.startingAdoptedRecording ? 'Starting...' : 'Start Capture on Adopted IP'}
                    </button>
                `}
            </div>
            ${recording?.outputPath ? `<p class="field-note identity-summary__capture-path"><code>${escapeHTML(recording.outputPath)}</code></p>` : ''}
        </div>
    `;
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
        'No ping replies.',
    );
}

function describePingOutcome(result) {
    if (!result || result.sent <= 0) {
        return null;
    }

    if (result.received >= result.sent) {
        return {label: 'Success', tone: 'success'};
    }
    if (result.received <= 0) {
        return {label: 'Failed', tone: 'warn'};
    }

    return {label: 'Partial', tone: 'warn'};
}

function renderPingOperationPanel(current, state) {
    const busy = state.pingingAdoptedIP;
    const result = state.pingResult;
    const outcome = describePingOutcome(result);

    return `
        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <h3>Ping</h3>
                </div>
                ${outcome ? pill(outcome.label, outcome.tone) : pill('Idle')}
            </div>
            <p class="field-note">ICMP echo from <code>${escapeHTML(current.ip)}</code>.</p>

            <form id="adopted-ip-ping-form" class="ping-inline-form ping-inline-form--compact">
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

                <div class="form-actions form-actions--compact ping-inline-form__action">
                    <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                        ${busy ? 'Pinging...' : 'Send'}
                    </button>
                </div>
            </form>

            ${result ? `
                ${renderInlineMeta([
        {label: 'Status', value: outcome?.label || 'Complete'},
        {label: 'Source', value: result.sourceIP, code: true},
        {label: 'Target', value: result.targetIP, code: true},
        {label: 'Sent', value: result.sent},
        {label: 'Recv', value: result.received},
    ], {dense: true})}
            ` : ''}
        </section>
    `;
}

function renderPingResultPanel(state) {
    if (!state.pingResult) {
        return '';
    }

    const result = state.pingResult;
    const outcome = describePingOutcome(result);
    const summary = outcome
        ? `${outcome.label} · ${result.received}/${result.sent}`
        : `${result.received}/${result.sent}`;

    return renderFoldPanel({
        title: 'Ping result',
        summary,
        body: renderPingResultTable(result),
        open: true,
    });
}

function renderTCPServicePanel({formId, serviceName, serviceStatus, state, includeRootDirectory = false}) {
    const active = Boolean(serviceStatus?.active);
    const failed = Boolean(serviceStatus && !serviceStatus.active && serviceStatus.lastError);
    const busy = state.adoptedDetailsLoading || state.startingAdoptedTCPService || state.stoppingAdoptedTCPService;
    const starting = state.startingAdoptedTCPService === serviceName;
    const stopping = state.stoppingAdoptedTCPService === serviceName;
    const form = state.adoptedTCPServiceForm;
    const portField = serviceName === 'http' ? 'httpPort' : 'echoPort';
    const portValue = form[portField];
    const httpUseTLS = Boolean(form.httpUseTLS);
    const httpScriptName = String(form.httpScriptName || '');
    const httpScriptStatus = renderSurfaceScriptStatus(state.storedScripts, httpScriptName, SCRIPT_SURFACE_HTTP_SERVICE);
    const protocolLabel = serviceName === 'http'
        ? (serviceStatus?.useTLS ? 'HTTPS' : 'HTTP')
        : 'TCP';

    return `
        <section class="panel section-panel section-panel--compact form-panel service-panel">
            <div class="service-panel__status">
                ${serviceStatus ? renderInlineMeta([
        {label: 'Protocol', value: protocolLabel},
        {label: 'Port', value: serviceStatus.port || '—'},
        ...(serviceName === 'http' && serviceStatus.scriptName ? [{label: 'Script', value: serviceStatus.scriptName}] : []),
        ...(serviceStatus.startedAt ? [{label: 'Started', value: serviceStatus.startedAt}] : []),
        ...(includeRootDirectory && serviceStatus.rootDirectory ? [{label: 'Root', value: serviceStatus.rootDirectory, code: true}] : []),
    ], {dense: true}) : '<span></span>'}
                ${active ? pill('On', 'success') : failed ? pill('Failed', 'warn') : pill('Off')}
            </div>

            ${serviceStatus?.lastError ? renderMessageBanner('Service', serviceStatus.lastError) : ''}

            <form id="${formId}" class="form-stack form-stack--compact">
                <div class="compact-form-grid compact-form-grid--service">
                    <label class="form-field">
                        <span>Port</span>
                        <input
                            type="number"
                            min="1"
                            max="65535"
                            step="1"
                            inputmode="numeric"
                            value="${escapeHTML(portValue)}"
                            data-adopted-tcp-service-field="${escapeHTML(portField)}"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

                    ${includeRootDirectory ? `
                        <label class="form-field">
                            <span>Script</span>
                            <select
                                data-adopted-tcp-service-field="httpScriptName"
                                ${busy ? 'disabled' : ''}
                            >
                                ${renderScriptOptions(state.storedScripts, SCRIPT_SURFACE_HTTP_SERVICE, httpScriptName)}
                            </select>
                        </label>

                        <label class="form-field">
                            <span>Protocol</span>
                            <select
                                data-adopted-tcp-service-field="httpUseTLS"
                                ${busy ? 'disabled' : ''}
                            >
                                <option value="false" ${!httpUseTLS ? 'selected' : ''}>HTTP</option>
                                <option value="true" ${httpUseTLS ? 'selected' : ''}>HTTPS</option>
                            </select>
                        </label>

                        <label class="form-field form-field--wide">
                            <span>Root</span>
                            <div class="inline-field-action">
                                <input
                                    type="text"
                                    value="${escapeHTML(form.httpRootDirectory)}"
                                    autocomplete="off"
                                    spellcheck="false"
                                    data-adopted-tcp-service-field="httpRootDirectory"
                                    ${busy ? 'disabled' : ''}
                                />
                                <button class="ghost-button" type="button" data-choose-http-service-root-directory ${busy ? 'disabled' : ''}>
                                    Browse
                                </button>
                            </div>
                        </label>
                    ` : ''}
                </div>

                ${httpScriptStatus ? `<p class="field-note">${escapeHTML(httpScriptStatus)}</p>` : ''}

                <div class="form-actions form-actions--compact">
                    <button class="primary-button" type="submit" ${(busy || active) ? 'disabled' : ''}>
                        ${starting ? 'Starting...' : serviceStatus && !active ? 'Restart' : 'Start'}
                    </button>
                    <button class="danger-button" type="button" data-stop-adopted-tcp-service="${escapeHTML(serviceName)}" ${(busy || !active) ? 'disabled' : ''}>
                        ${stopping ? 'Stopping...' : 'Stop'}
                    </button>
                </div>
            </form>
        </section>
    `;
}

function renderInfoTab({details, interfaces, item, state}) {
    const current = details ?? item;
    const busy = state.updatingAdoption;
    const interfaceOptions = renderInterfaceOptions(interfaces, state.adoptedEditForm.interfaceName, 'No adoptable interfaces available');
    const editBody = `
        <form id="adopted-ip-edit-form" class="form-stack form-stack--compact">
            <div class="compact-form-grid">
                ${renderIdentityFields({
        disabled: busy || !interfaces.length,
        fieldAttribute: 'data-adopted-edit-field',
        form: state.adoptedEditForm,
        interfaceOptions,
        labelNote: 'Stable name.',
        ipNote: '',
        gatewayNote: 'Optional next hop.',
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
    `;

    return `
        <section class="panel section-panel section-panel--compact identity-summary">
            <div class="identity-summary__header">
                <div>
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

            ${renderInfoScriptControl(state)}
            ${renderInfoCaptureControl(current, state)}
        </section>

        ${renderFoldPanel({
        title: 'Edit identity',
        summary: current.ip,
        body: editBody,
    })}
    `;
}

function renderOperationsTab(current, state) {
    return `
        ${renderPingOperationPanel(current, state)}
        ${state.pingError ? renderMessageBanner('Ping failed', state.pingError) : ''}
        ${renderPingResultPanel(state)}
    `;
}

function renderServicesTab(details, state) {
    const selectedService = state.selectedAdoptedService === 'echo' ? 'echo' : 'http';

    return `
        ${renderButtonTabs(ADOPTED_SERVICE_TABS, selectedService, 'data-adopted-service-tab', 'Adopted IP services')}
        ${selectedService === 'echo'
        ? renderTCPServicePanel({
            formId: 'adopted-echo-service-form',
            serviceName: 'echo',
            serviceStatus: findTCPService(details, 'echo'),
            state,
        })
        : renderTCPServicePanel({
            formId: 'adopted-http-service-form',
            serviceName: 'http',
            serviceStatus: findTCPService(details, 'http'),
            state,
            includeRootDirectory: true,
        })}
    `;
}

export function renderAdoptIPAddressForm({interfaceOptions, state}) {
    if (state.interfaceSelectionLoading && !state.interfaceSelection && state.adoptMode === 'raw') {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('Adopt IP')}
                ${renderStateLayout('single-panel-layout', 'Loading interfaces', 'Collecting interface choices.')}
            </div>
        `;
    }

    const rawDisabled = state.adopting || !interfaceOptions.length;
    const selectOptions = renderInterfaceOptions(interfaceOptions, state.adoptForm.interfaceName, 'No adoptable interfaces available');
    const modeTabs = renderButtonTabs(ADOPT_MODES, state.adoptMode, 'data-adopt-mode', 'Adoption modes');

    const body = state.adoptMode === 'stored'
        ? `
            <section class="panel section-panel section-panel--compact">
                <div class="section-heading section-heading--tight">
                    <div>
                        <h3>Saved identities</h3>
                        <p>Reuse a saved identity. Manage them from Saved Identities.</p>
                    </div>
                </div>
                ${renderStoredConfigList(state, 'chooser')}
            </section>
        `
        : `
            <section class="panel section-panel section-panel--compact form-panel">
                <div class="section-heading section-heading--tight">
                    <div>
                        <h3>New identity</h3>
                        <p>Enter only what Kraken needs.</p>
                    </div>
                </div>

                <form id="adopt-ip-form" class="form-stack form-stack--compact">
                    <div class="compact-form-grid">
                        ${renderIdentityFields({
        disabled: rawDisabled,
        fieldAttribute: 'data-adopt-field',
        form: state.adoptForm,
        interfaceOptions: selectOptions,
        labelNote: 'Stable name.',
        ipNote: '',
        gatewayNote: 'Optional next hop.',
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
            ${renderModuleTopbar('Adopt IP')}

            <main class="single-panel-layout">
                ${state.interfaceSelection?.warning ? renderMessageBanner('pcap', state.interfaceSelection.warning) : ''}
                ${state.interfaceSelectionError ? renderMessageBanner('Interfaces', state.interfaceSelectionError) : ''}
                ${state.adoptError ? renderMessageBanner('Adopt', state.adoptError) : ''}
                ${modeTabs}
                ${body}
            </main>
        </div>
    `;
}

export function renderAdoptedIPAddressView({details, interfaceOptions, item, state}) {
    if (!item) {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('')}
                ${renderStateLayout('single-panel-layout', 'No adopted IP selected', 'Return home and open an adopted identity.')}
            </div>
        `;
    }

    const current = details ?? item;

    let tabContent = renderInfoTab({details, interfaces: interfaceOptions, item, state});

    if (state.selectedAdoptedTab === 'operations') {
        tabContent = renderOperationsTab(current, state);
    } else if (state.selectedAdoptedTab === 'services') {
        tabContent = renderServicesTab(details, state);
    }

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('')}
            <main class="single-panel-layout single-panel-layout--wide">
                ${state.adoptedUpdateError ? renderMessageBanner('Update', state.adoptedUpdateError) : ''}
                ${state.adoptedScriptError ? renderMessageBanner('Scripts', state.adoptedScriptError) : ''}
                ${state.adoptedRecordingError ? renderMessageBanner('Recording', state.adoptedRecordingError) : ''}
                ${state.adoptedRecordingNotice ? renderMessageBanner('Recording', state.adoptedRecordingNotice) : ''}
                ${state.adoptedTCPServiceError ? renderMessageBanner('Service', state.adoptedTCPServiceError) : ''}
                ${state.adoptedTCPServiceNotice ? renderMessageBanner('Service', state.adoptedTCPServiceNotice) : ''}
                ${state.adoptedDetailsError ? renderMessageBanner('Details', state.adoptedDetailsError) : ''}
                ${renderButtonTabs(ADOPTED_TABS, state.selectedAdoptedTab, 'data-adopted-tab', 'Adopted IP sections')}
                ${tabContent}
            </main>
        </div>
    `;
}
