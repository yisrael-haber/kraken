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
    SCRIPT_SURFACE_APPLICATION,
    SCRIPT_SURFACE_TRANSPORT,
} from '../scriptModel';

const ADOPTED_TABS = [
    ['info', 'Info'],
    ['operations', 'Ops'],
    ['services', 'Services'],
];

const ADOPT_MODES = [
    ['stored', 'Saved'],
    ['custom', 'Custom'],
];

const DNS_QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'];
const DNS_TRANSPORTS = ['udp', 'tcp'];

function renderFieldNote(text) {
    if (!text) {
        return '';
    }

    return `<small class="field-note">${escapeHTML(text)}</small>`;
}

function renderCustomAdoptFields({disabled, form, interfaceOptions}) {
    return `
        <label class="adopt-control adopt-control--label">
            <span>Label</span>
            <input
                type="text"
                name="label"
                value="${escapeHTML(form.label)}"
                autocomplete="off"
                spellcheck="false"
                data-adopt-field="label"
                ${disabled ? 'disabled' : ''}
            />
        </label>

        <label class="adopt-control adopt-control--interface">
            <span>Interface</span>
            <select
                name="interfaceName"
                data-adopt-field="interfaceName"
                ${disabled ? 'disabled' : ''}
            >
                ${interfaceOptions}
            </select>
        </label>

        <label class="adopt-control adopt-control--ip">
            <span>IP</span>
            <input
                type="text"
                name="ip"
                value="${escapeHTML(form.ip)}"
                placeholder="192.168.56.50"
                autocomplete="off"
                spellcheck="false"
                data-adopt-field="ip"
                ${disabled ? 'disabled' : ''}
            />
        </label>

        <label class="adopt-control adopt-control--prefix">
            <span>Prefix</span>
            <input
                type="text"
                name="subnetPrefix"
                value="${escapeHTML(form.subnetPrefix || '')}"
                placeholder="24"
                autocomplete="off"
                spellcheck="false"
                inputmode="numeric"
                data-adopt-field="subnetPrefix"
                ${disabled ? 'disabled' : ''}
            />
        </label>

        <label class="adopt-control adopt-control--gateway">
            <span>Gateway</span>
            <input
                type="text"
                name="defaultGateway"
                value="${escapeHTML(form.defaultGateway || '')}"
                placeholder="Optional"
                autocomplete="off"
                spellcheck="false"
                data-adopt-field="defaultGateway"
                ${disabled ? 'disabled' : ''}
            />
        </label>

        <label class="adopt-control adopt-control--mac">
            <span>MAC</span>
            <input
                type="text"
                name="mac"
                value="${escapeHTML(form.mac)}"
                placeholder="Optional"
                autocomplete="off"
                spellcheck="false"
                data-adopt-field="mac"
                ${disabled ? 'disabled' : ''}
            />
        </label>

        <label class="adopt-control adopt-control--mtu">
            <span>MTU</span>
            <input
                type="text"
                name="mtu"
                value="${escapeHTML(form.mtu || '')}"
                placeholder="Iface"
                autocomplete="off"
                spellcheck="false"
                inputmode="numeric"
                data-adopt-field="mtu"
                ${disabled ? 'disabled' : ''}
            />
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

function findStoredScript(storedScripts, name, surface = SCRIPT_SURFACE_TRANSPORT) {
    return storedScripts.find((item) => item.name === name && item.surface === surface) || null;
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
    const transportScriptName = state.adoptedTransportScriptName || '';
    const applicationScriptName = state.adoptedApplicationScriptName || '';
    const transportStatus = renderSurfaceScriptStatus(state.storedScripts, transportScriptName, SCRIPT_SURFACE_TRANSPORT);
    const applicationStatus = renderSurfaceScriptStatus(state.storedScripts, applicationScriptName, SCRIPT_SURFACE_APPLICATION);

    return `
        <form id="adopted-script-form" class="identity-summary__script-form">
            <div class="identity-summary__script-grid">
                <label class="form-field identity-summary__inline-field">
                    <span>Transport script</span>
                    <select
                        data-adopted-transport-script-name
                        ${busy ? 'disabled' : ''}
                    >
                        ${renderScriptOptions(state.storedScripts, SCRIPT_SURFACE_TRANSPORT, transportScriptName)}
                    </select>
                </label>
                <label class="form-field identity-summary__inline-field">
                    <span>Application script</span>
                    <select
                        data-adopted-application-script-name
                        ${busy ? 'disabled' : ''}
                    >
                        ${renderScriptOptions(state.storedScripts, SCRIPT_SURFACE_APPLICATION, applicationScriptName)}
                    </select>
                </label>
            </div>
            <div class="form-actions form-actions--compact identity-summary__script-actions">
                <button class="command-button command-button--primary" type="submit" ${busy ? 'disabled' : ''}>
                    ${state.savingAdoptedScript ? 'Saving...' : 'Save'}
                </button>
            </div>
        </form>
        ${transportStatus ? `<p class="field-note">${escapeHTML(transportStatus)}</p>` : ''}
        ${applicationStatus ? `<p class="field-note">${escapeHTML(applicationStatus)}</p>` : ''}
    `;
}

function renderRuntimeScriptError(details) {
    const item = details?.scriptError || null;
    if (!item?.lastError) {
        return '';
    }

    const context = [
        item.surface,
        item.scriptName,
        item.stage,
        item.direction,
    ].filter(Boolean).join(' / ');
    const message = context
        ? `${context}: ${item.lastError}`
        : item.lastError;

    return renderMessageBanner('Script runtime', message);
}

function renderCaptureStatus(details) {
    const capture = details?.capture || null;
    if (!capture?.lastError) {
        return '';
    }

    return renderMessageBanner('Capture', capture.lastError);
}

function renderInfoCaptureControl(current, state) {
    const recording = current.recording || null;
    const active = Boolean(recording?.active);
    const busy = state.startingAdoptedRecording || state.stoppingAdoptedRecording || state.adoptedDetailsLoading;

    return `
        <div class="identity-summary__capture">
            <div class="identity-summary__capture-action">
                ${active ? `
                    <button class="command-button command-button--danger" type="button" data-stop-adopted-recording ${busy ? 'disabled' : ''}>
                        ${state.stoppingAdoptedRecording ? 'Stopping...' : 'Stop Capture on Adopted IP'}
                    </button>
                ` : `
                    <button class="command-button command-button--primary" type="button" data-start-adopted-recording ${busy ? 'disabled' : ''}>
                        ${state.startingAdoptedRecording ? 'Starting...' : 'Start Capture on Adopted IP'}
                    </button>
                `}
            </div>
            ${recording?.outputPath ? `<p class="field-note identity-summary__capture-path"><code>${escapeHTML(recording.outputPath)}</code></p>` : ''}
        </div>
    `;
}

function describeDNSOutcome(result) {
    if (!result) {
        return null;
    }
    if ((result.responseCode || '') === 'No Error') {
        return {label: 'Success', tone: 'success'};
    }
    if (result.responseCode) {
        return {label: result.responseCode, tone: 'warn'};
    }
    return {label: 'Complete', tone: 'success'};
}

function renderDNSOperationPanel(current, state) {
    const busy = state.resolvingAdoptedDNS;
    const result = state.dnsResult;
    const outcome = describeDNSOutcome(result);

    return `
        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <h3>DNS</h3>
                </div>
                ${outcome ? pill(outcome.label, outcome.tone) : pill('Idle')}
            </div>

            <form id="adopted-ip-dns-form" class="dns-inline-form">
                <label class="form-field">
                    <span>Server</span>
                    <input
                        type="text"
                        name="server"
                        value="${escapeHTML(state.dnsForm.server)}"
                        placeholder="8.8.8.8 or 8.8.8.8:53"
                        autocomplete="off"
                        spellcheck="false"
                        data-dns-field="server"
                        ${busy ? 'disabled' : ''}
                    />
                </label>

                <label class="form-field">
                    <span>Name</span>
                    <input
                        type="text"
                        name="name"
                        value="${escapeHTML(state.dnsForm.name)}"
                        placeholder="example.com"
                        autocomplete="off"
                        spellcheck="false"
                        data-dns-field="name"
                        ${busy ? 'disabled' : ''}
                    />
                </label>

                <label class="form-field dns-inline-form__type">
                    <span>Type</span>
                    <select name="type" data-dns-field="type" ${busy ? 'disabled' : ''}>
                        ${DNS_QUERY_TYPES.map((value) => `
                            <option value="${escapeHTML(value)}" ${state.dnsForm.type === value ? 'selected' : ''}>
                                ${escapeHTML(value)}
                            </option>
                        `).join('')}
                    </select>
                </label>

                <label class="form-field dns-inline-form__transport">
                    <span>Transport</span>
                    <select name="transport" data-dns-field="transport" ${busy ? 'disabled' : ''}>
                        ${DNS_TRANSPORTS.map((value) => `
                            <option value="${escapeHTML(value)}" ${state.dnsForm.transport === value ? 'selected' : ''}>
                                ${escapeHTML(value.toUpperCase())}
                            </option>
                        `).join('')}
                    </select>
                </label>

                <label class="form-field dns-inline-form__timeout">
                    <span>Timeout</span>
                    <input
                        type="number"
                        name="timeoutMillis"
                        value="${escapeHTML(state.dnsForm.timeoutMillis)}"
                        min="1"
                        step="1"
                        inputmode="numeric"
                        data-dns-field="timeoutMillis"
                        ${busy ? 'disabled' : ''}
                    />
                </label>

                <div class="form-actions form-actions--compact dns-inline-form__action">
                    <button class="command-button command-button--primary" type="submit" ${busy ? 'disabled' : ''}>
                        ${busy ? 'Resolving...' : 'Send'}
                    </button>
                </div>
            </form>

            ${result ? `
                ${renderInlineMeta([
        {label: 'Source', value: result.sourceIP, code: true},
        {label: 'Server', value: result.server, code: true},
        {label: 'Name', value: result.name, code: true},
        {label: 'Type', value: result.type},
        {label: 'Xport', value: String(result.transport || '').toUpperCase()},
        {label: 'RTT', value: `${Number(result.rttMillis || 0).toFixed(2)} ms`},
    ], {dense: true})}
            ` : ''}
        </section>
    `;
}

function renderDNSResultPanel(state) {
    const result = state.dnsResult;
    if (!result) {
        return '';
    }

    const records = result.records || [];
    const summary = `${result.responseCode || 'Complete'} · ${records.length} records`;
    const rows = records.map((item) => `
        <tr>
            <td><code>${escapeHTML(item || '')}</code></td>
        </tr>
    `);

    return `
        ${renderFoldPanel({
        title: 'DNS result',
        summary,
        body: `
            ${renderInlineMeta([
            {label: 'Response ID', value: String(result.responseID || 0)},
            {label: 'rcode', value: result.responseCode || ''},
            {label: 'Records', value: String(records.length)},
        ], {dense: true})}
            ${renderActivityTableContent(['Record'], rows, 'No DNS records.')}
        `,
        open: true,
    })}
    `;
}

function renderServiceField(state, serviceName, field, value, disabled) {
    const safeValue = String(value || '');
    const fieldName = escapeHTML(field.name);
    const serviceAttr = `data-adopted-service-name="${escapeHTML(serviceName)}"`;
    const fieldAttr = `data-adopted-service-field="${fieldName}"`;

    if (field.type === 'select') {
        return `
            <label class="form-field">
                <span>${escapeHTML(field.label)}</span>
                <select ${serviceAttr} ${fieldAttr} ${disabled ? 'disabled' : ''}>
                    ${(field.options || []).map((option) => `
                        <option value="${escapeHTML(option.value)}" ${option.value === safeValue ? 'selected' : ''}>
                            ${escapeHTML(option.label)}
                        </option>
                    `).join('')}
                </select>
            </label>
        `;
    }

    if (field.type === 'directory') {
        return `
            <label class="form-field form-field--wide">
                <span>${escapeHTML(field.label)}</span>
                <div class="inline-field-action">
                    <input
                        type="text"
                        value="${escapeHTML(safeValue)}"
                        autocomplete="off"
                        spellcheck="false"
                        ${serviceAttr}
                        ${fieldAttr}
                        ${disabled ? 'disabled' : ''}
                    />
                    <button
                        class="command-button command-button--secondary"
                        type="button"
                        data-choose-service-directory
                        ${serviceAttr}
                        ${fieldAttr}
                        ${disabled ? 'disabled' : ''}
                    >
                        Browse
                    </button>
                </div>
            </label>
        `;
    }

    if (field.type === 'stored_script') {
        return `
            <label class="form-field">
                <span>${escapeHTML(field.label)}</span>
                <select ${serviceAttr} ${fieldAttr} ${disabled ? 'disabled' : ''}>
                    ${renderScriptOptions(state.storedScripts, field.scriptSurface || SCRIPT_SURFACE_TRANSPORT, safeValue)}
                </select>
            </label>
        `;
    }

    const inputType = field.type === 'secret'
        ? 'password'
        : field.type === 'port'
            ? 'number'
            : 'text';
    const extraAttributes = field.type === 'port'
        ? 'min="1" max="65535" step="1" inputmode="numeric"'
        : 'autocomplete="off" spellcheck="false"';

    return `
        <label class="form-field">
            <span>${escapeHTML(field.label)}</span>
            <input
                type="${inputType}"
                value="${escapeHTML(safeValue)}"
                placeholder="${escapeHTML(field.placeholder || '')}"
                ${extraAttributes}
                ${serviceAttr}
                ${fieldAttr}
                ${disabled ? 'disabled' : ''}
            />
        </label>
    `;
}

function renderServicePanel({definition, serviceTabs, selectedService, state}) {
    const serviceName = definition.service;
    const busy = state.adoptedDetailsLoading || state.startingAdoptedService;
    const starting = state.startingAdoptedService === serviceName;
    const stopping = state.stoppingAdoptedService === serviceName;
    const form = state.adoptedServiceForms[serviceName] || {};
    const scriptField = (definition.fields || []).find((field) => field.type === 'stored_script') || null;
    const scriptStatus = scriptField
        ? renderSurfaceScriptStatus(state.storedScripts, String(form[scriptField.name] || ''), scriptField.scriptSurface || SCRIPT_SURFACE_TRANSPORT)
        : '';

    return `
        <section class="services-start-panel">
            <form id="adopted-service-form" class="service-start-form">
                <div class="service-type-field">
                <span>Type</span>
                    <nav class="service-type-control" aria-label="Adopted IP services">
                        ${serviceTabs.map(([value, label]) => `
                            <button
                                class="service-type-button ${selectedService === value ? 'is-active' : ''}"
                                type="button"
                                data-adopted-service-tab="${escapeHTML(value)}"
                                aria-pressed="${selectedService === value ? 'true' : 'false'}"
                            >
                                ${escapeHTML(label)}
                            </button>
                        `).join('')}
                    </nav>
                </div>

                ${(definition.fields || []).map((field) => renderServiceField(state, serviceName, field, form[field.name], busy)).join('')}

                ${scriptStatus ? `<p class="field-note">${escapeHTML(scriptStatus)}</p>` : ''}

                <div class="service-start-action">
                    <button class="command-button command-button--primary service-start-button" type="submit" ${busy ? 'disabled' : ''}>
                        ${starting ? 'Starting...' : 'Start'}
                    </button>
                </div>
            </form>
        </section>
    `;
}

function findServiceLabel(serviceDefinitions, serviceName) {
    return serviceDefinitions.find((item) => item.service === serviceName)?.label || serviceName;
}

function renderLiveServicesTable(details, state) {
    const items = [...(details?.services || [])].sort((left, right) => String(left.service || '').localeCompare(String(right.service || '')));
    if (!items.length) {
        return '<div class="empty-state">No live services.</div>';
    }

    const rows = items.map((item) => {
        const scriptError = item.scriptError?.lastError
            ? `${item.scriptError.scriptName || 'script'}: ${item.scriptError.lastError}`
            : '';
        return `
        <tr>
            <td>${escapeHTML(findServiceLabel(state.serviceDefinitions, item.service))}</td>
            <td><code>${escapeHTML(item.port || '')}</code></td>
            <td>${(item.summary || []).length ? renderInlineMeta(item.summary, {dense: true}) : '-'}</td>
            <td>${scriptError ? escapeHTML(scriptError) : item.lastError ? escapeHTML(item.lastError) : item.startedAt ? `<time>${escapeHTML(item.startedAt)}</time>` : '-'}</td>
            <td class="activity-actions">
                <button
                    class="command-button command-button--danger service-free-button"
                    type="button"
                    data-stop-adopted-service="${escapeHTML(item.service)}"
                    ${state.stoppingAdoptedService ? 'disabled' : ''}
                >
                    ${state.stoppingAdoptedService === item.service ? 'Freeing...' : 'Stop + Free'}
                </button>
            </td>
        </tr>
    `;
    });

    return renderActivityTableContent(
        ['Service', 'Port', 'Summary', 'Started / Error', ''],
        rows,
        'No live services.',
    );
}

function renderInfoTab({details, item, state}) {
    const current = details ?? item;
    const busy = state.updatingAdoptedMTU;
    const editBody = `
        <form id="adopted-mtu-form" class="form-stack form-stack--compact">
            ${renderInlineMeta([
        {label: 'IP', value: current.ip, code: true},
        {label: 'Prefix', value: `/${current.subnetPrefix || 24}`, code: true},
        ...(current.defaultGateway ? [{label: 'Gateway', value: current.defaultGateway, code: true}] : []),
        {label: 'MAC', value: current.mac, code: true},
        {label: 'Iface', value: current.interfaceName},
    ], {dense: true})}
            <div class="compact-form-grid">
                <label class="form-field">
                    <span>MTU</span>
                    <input
                        type="text"
                        name="mtu"
                        value="${current.mtu ? escapeHTML(String(current.mtu)) : ''}"
                        placeholder="Iface"
                        autocomplete="off"
                        spellcheck="false"
                        inputmode="numeric"
                        ${busy ? 'disabled' : ''}
                    />
                    ${renderFieldNote('')}
                </label>
            </div>

            <div class="form-actions form-actions--compact">
                <button class="command-button command-button--primary" type="submit" ${busy ? 'disabled' : ''}>
                        ${state.updatingAdoptedMTU ? 'Saving...' : 'Save'}
                    </button>
                    <button class="command-button command-button--secondary" type="reset" ${busy ? 'disabled' : ''}>Reset</button>
                </div>
            </form>
    `;

    return `
        <section class="panel section-panel section-panel--compact identity-summary">
            <div class="identity-summary__header">
                <div class="adopted-identity-title adopted-identity-title--summary">
                    <strong>${escapeHTML(current.label || 'Adopted identity')}</strong>
                    <code>${escapeHTML(current.ip)}</code>
                </div>
            </div>

            ${renderInfoScriptControl(state)}
            ${renderInfoCaptureControl(current, state)}
        </section>

        ${renderFoldPanel({
        title: 'Runtime MTU',
        summary: current.ip,
        body: editBody,
    })}
    `;
}

function renderOperationsTab(current, state) {
    return `
        ${renderDNSOperationPanel(current, state)}
        ${state.dnsError ? renderMessageBanner('DNS failed', state.dnsError) : ''}
        ${renderDNSResultPanel(state)}
    `;
}

function renderServicesTab(details, state) {
    if (state.serviceDefinitionsLoading && !state.serviceDefinitions.length) {
        return '<div class="empty-state">Loading services.</div>';
    }
    if (!state.serviceDefinitions.length) {
        return '<div class="empty-state">No services.</div>';
    }

    const selectedService = state.serviceDefinitions.some((item) => item.service === state.selectedAdoptedService)
        ? state.selectedAdoptedService
        : state.serviceDefinitions[0].service;
    const selectedDefinition = state.serviceDefinitions.find((item) => item.service === selectedService) || state.serviceDefinitions[0];
    const serviceTabs = state.serviceDefinitions.map((item) => [item.service, item.label]);

    return `
        <div class="services-workspace">
            ${renderServicePanel({
        definition: selectedDefinition,
        serviceTabs,
        selectedService,
        state,
    })}
            <section class="services-live-panel">
                <div class="section-heading section-heading--tight">
                    <h3>Live services</h3>
                </div>
                ${renderLiveServicesTable(details, state)}
            </section>
        </div>
    `;
}

export function renderAdoptIPAddressForm({interfaceOptions, state}) {
    if (state.interfaceSelectionLoading && !state.interfaceSelection && state.adoptMode === 'custom') {
        return `
            <div class="adopt-screen">
                <aside class="adopt-rail">
                    <button class="adopt-back" type="button" data-go-home>Back</button>
                    <h1>Adopt IP</h1>
                </aside>
                <main class="adopt-workspace">
                    <div class="adopt-empty">
                        <strong>Loading interfaces</strong>
                        <span>Collecting interface choices.</span>
                    </div>
                </main>
            </div>
        `;
    }

    const customDisabled = state.adopting || !interfaceOptions.length;
    const selectOptions = renderInterfaceOptions(interfaceOptions, state.adoptForm.interfaceName, 'No adoptable interfaces available');
    const messages = [
        state.interfaceSelection?.warning ? ['pcap', state.interfaceSelection.warning] : null,
        state.interfaceSelectionError ? ['Interfaces', state.interfaceSelectionError] : null,
        state.adoptError ? ['Adopt', state.adoptError] : null,
    ].filter(Boolean).map(([title, message]) => `
        <div class="adopt-message">
            <strong>${escapeHTML(title)}</strong>
            <span>${escapeHTML(message)}</span>
        </div>
    `).join('');

    const body = state.adoptMode === 'stored'
        ? `
            <section class="adopt-stored-pane">
                <header class="adopt-pane-heading">
                    <h2>Saved identities</h2>
                </header>
                ${renderStoredConfigList(state, 'chooser')}
            </section>
        `
        : `
            <section class="adopt-custom-pane">
                <form id="adopt-ip-form" class="adopt-custom-form">
                    <div class="adopt-custom-fields">
                        ${renderCustomAdoptFields({
        disabled: customDisabled,
        form: state.adoptForm,
        interfaceOptions: selectOptions,
    })}
                    </div>

                    <div class="adopt-form-actions">
                        <button class="adopt-submit" type="submit" ${customDisabled ? 'disabled' : ''}>
                            ${state.adopting ? 'Adopting...' : 'Adopt'}
                        </button>
                        <button class="adopt-cancel" type="button" data-go-home>Cancel</button>
                    </div>
                </form>
            </section>
        `;

    return `
        <div class="adopt-screen">
            <aside class="adopt-rail">
                <button class="adopt-back" type="button" data-go-home>Back</button>
                <div>
                    <h1>Adopt IP</h1>
                    <p>${state.adoptMode === 'custom' ? 'Custom' : 'Saved'}</p>
                </div>
                <nav class="adopt-mode" aria-label="Adoption modes">
                    ${ADOPT_MODES.map(([value, label]) => `
                        <button
                            class="adopt-mode__button ${state.adoptMode === value ? 'is-active' : ''}"
                            type="button"
                            data-adopt-mode="${value}"
                            aria-pressed="${state.adoptMode === value ? 'true' : 'false'}"
                        >
                            ${escapeHTML(label)}
                        </button>
                    `).join('')}
                </nav>
            </aside>
            <main class="adopt-workspace">
                ${messages}
                ${body}
            </main>
        </div>
    `;
}

export function renderAdoptedIPAddressView({details, item, state}) {
    if (!item) {
        return `
            <div class="module-frame module-frame--single">
                ${renderModuleTopbar('')}
                ${renderStateLayout('single-panel-layout', 'No adopted IP selected', 'Return home and open an adopted identity.')}
            </div>
        `;
    }

    const current = details ?? item;

    let tabContent = renderInfoTab({details, item, state});

    if (state.selectedAdoptedTab === 'operations') {
        tabContent = renderOperationsTab(current, state);
    } else if (state.selectedAdoptedTab === 'services') {
        tabContent = renderServicesTab(details, state);
    }

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('')}
            <main class="single-panel-layout single-panel-layout--wide">
                ${renderCaptureStatus(details)}
                ${renderRuntimeScriptError(details)}
                ${state.adoptedMTUError ? renderMessageBanner('MTU', state.adoptedMTUError) : ''}
                ${state.adoptedScriptError ? renderMessageBanner('Scripts', state.adoptedScriptError) : ''}
                ${state.adoptedRecordingError ? renderMessageBanner('Recording', state.adoptedRecordingError) : ''}
                ${state.adoptedRecordingNotice ? renderMessageBanner('Recording', state.adoptedRecordingNotice) : ''}
                ${state.adoptedServiceError ? renderMessageBanner('Service', state.adoptedServiceError) : ''}
                ${state.adoptedServiceNotice ? renderMessageBanner('Service', state.adoptedServiceNotice) : ''}
                ${state.adoptedDetailsError ? renderMessageBanner('Details', state.adoptedDetailsError) : ''}
                ${renderButtonTabs(ADOPTED_TABS, state.selectedAdoptedTab, 'data-adopted-tab', 'Adopted IP sections')}
                ${tabContent}
            </main>
        </div>
    `;
}
