import {
    escapeHTML,
    pill,
    renderMessageBanner,
    renderModuleTopbar,
    renderStateLayout,
} from './common';
import {SERVICE_DEFINITIONS, findServiceDefinition} from '../app/state';

const DNS_QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'];
const DNS_TRANSPORTS = ['udp', 'tcp'];

function renderInlineMeta(items) {
    return `
        <div class="inline-meta wa-cluster wa-gap-xs">
            ${items.map((item) => `
                <div class="meta-chip wa-cluster wa-gap-2xs">
                    <span class="wa-caption-2xs wa-text-uppercase">${escapeHTML(item.label)}</span>
                    ${item.code ? `<code>${escapeHTML(item.value)}</code>` : `<strong>${escapeHTML(item.value)}</strong>`}
                </div>
            `).join('')}
        </div>
    `;
}

function renderIdentityWAOptions(items) {
    return items.map((item) => {
        const label = item.label && item.label !== item.ip
            ? `${item.label} (${item.ip})`
            : item.ip;
        return `<wa-option value="${escapeHTML(item.ip)}">${escapeHTML(label)}</wa-option>`;
    }).join('');
}

function renderWAOptions(values, label = (value) => value) {
    return values.map((value) => `
        <wa-option value="${escapeHTML(value)}">${escapeHTML(label(value))}</wa-option>
    `).join('');
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
    ` : `<div class="empty-state wa-caption-s">${escapeHTML(emptyText)}</div>`;
}

function findStoredScript(storedScripts, name) {
    return storedScripts.find((item) => item.name === name) || null;
}

function renderScriptOptions(storedScripts, selectedName) {
    const items = ['<wa-option value="">None</wa-option>'];
    const availableScripts = storedScripts.filter((item) => item.available);

    for (const script of availableScripts) {
        items.push(`
            <wa-option value="${escapeHTML(script.name)}">
                ${escapeHTML(script.name)}
            </wa-option>
        `);
    }

    if (selectedName) {
        const selectedScript = findStoredScript(storedScripts, selectedName);
        if (!selectedScript || !selectedScript.available) {
            const suffix = selectedScript ? ' (Unavailable)' : ' (Missing)';
            items.push(`
                <wa-option value="${escapeHTML(selectedName)}">
                    ${escapeHTML(`${selectedName}${suffix}`)}
                </wa-option>
            `);
        }
    }

    return items.join('');
}

function renderScriptStatus(storedScripts, selectedName) {
    if (!selectedName) {
        return '';
    }

    const selectedScript = findStoredScript(storedScripts, selectedName);
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
    const transportStatus = renderScriptStatus(state.storedScripts, transportScriptName);

    return `
        <form id="adopted-script-form" class="identity-setting wa-stack wa-gap-xs">
            <wa-select label="Transport script" value="${escapeHTML(transportScriptName)}" appearance="filled" size="xs" data-adopted-transport-script-name ${busy ? 'disabled' : ''}>
                ${renderScriptOptions(state.storedScripts, transportScriptName)}
            </wa-select>
            <div class="form-actions wa-cluster wa-gap-xs">
                <wa-button variant="brand" appearance="accent" size="xs" type="submit" ${state.savingAdoptedScript ? 'loading' : ''} ${busy ? 'disabled' : ''}>Save</wa-button>
            </div>
            ${transportStatus ? `<p class="field-note wa-caption-xs">${escapeHTML(transportStatus)}</p>` : ''}
        </form>
    `;
}

function renderRuntimeScriptError(details) {
    const item = details?.scriptError || null;
    if (!item?.lastError) {
        return '';
    }

    const context = [
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
        <div class="identity-capture wa-stack wa-gap-2xs wa-align-items-end">
            <div class="identity-capture__actions wa-cluster wa-gap-xs">
                ${active ? pill('Capturing', 'success') : ''}
                ${active ? `
                    <wa-button appearance="outlined" size="xs" type="button" data-stop-adopted-recording ${state.stoppingAdoptedRecording ? 'loading' : ''} ${busy ? 'disabled' : ''}>Stop capture</wa-button>
                ` : `
                    <wa-button variant="brand" appearance="accent" size="xs" type="button" data-start-adopted-recording ${state.startingAdoptedRecording ? 'loading' : ''} ${busy ? 'disabled' : ''}>Start capture</wa-button>
                `}
            </div>
            ${recording?.outputPath ? `
                <div class="path-value wa-cluster wa-gap-2xs">
                    <code class="identity-capture__path">${escapeHTML(recording.outputPath)}</code>
                    <wa-copy-button value="${escapeHTML(recording.outputPath)}" copy-label="Copy capture path" tooltip="copy"></wa-copy-button>
                </div>
            ` : ''}
        </div>
    `;
}

function renderDNSOperationPanel(state) {
    const busy = state.resolvingAdoptedDNS;
    const result = state.dnsResult;

    return `
        <section class="operation-panel wa-stack wa-gap-s">
            <form id="adopted-ip-dns-form" class="operation-form wa-grid wa-gap-s">
                <wa-input label="Name" type="text" name="name" value="${escapeHTML(state.dnsForm.name)}" placeholder="example.com" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-dns-field="name" ${busy ? 'disabled' : ''}></wa-input>
                <wa-input label="Server" type="text" name="server" value="${escapeHTML(state.dnsForm.server)}" placeholder="8.8.8.8:53" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-dns-field="server" ${busy ? 'disabled' : ''}></wa-input>
                <wa-select label="Type" name="type" value="${escapeHTML(state.dnsForm.type)}" appearance="filled" size="xs" data-dns-field="type" ${busy ? 'disabled' : ''}>
                    ${renderWAOptions(DNS_QUERY_TYPES)}
                </wa-select>
                <wa-select label="Transport" name="transport" value="${escapeHTML(state.dnsForm.transport)}" appearance="filled" size="xs" data-dns-field="transport" ${busy ? 'disabled' : ''}>
                    ${renderWAOptions(DNS_TRANSPORTS, (value) => value.toUpperCase())}
                </wa-select>
                <wa-number-input label="Timeout (ms)" name="timeoutMillis" value="${escapeHTML(state.dnsForm.timeoutMillis)}" min="1" step="1" appearance="filled" size="xs" data-dns-field="timeoutMillis" ${busy ? 'disabled' : ''}></wa-number-input>
                <div class="form-actions wa-cluster wa-gap-xs wa-align-self-end">
                    <wa-button variant="brand" appearance="accent" size="xs" type="submit" ${busy ? 'loading disabled' : ''}>Resolve</wa-button>
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
    ])}
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
    const rows = records.map((record) => `
        <tr>
            <td>${escapeHTML(record.section)}</td>
            <td><code>${escapeHTML(record.name)}</code></td>
            <td>${escapeHTML(record.type)} · ${escapeHTML(record.class)}</td>
            <td>${escapeHTML(record.ttl)}s</td>
            <td><code>${escapeHTML(record.value)}</code></td>
        </tr>
    `);

    return `
        <section class="content-column dns-result wa-stack wa-gap-s">
            <header class="dns-result__header wa-split wa-gap-s">
                <h3 class="wa-heading-s">Result</h3>
                <span class="wa-caption-xs">${escapeHTML(summary)}</span>
            </header>
            ${renderInlineMeta([
            {label: 'Response ID', value: String(result.responseID || 0)},
            {label: 'rcode', value: result.responseCode || ''},
            {label: 'Records', value: String(records.length)},
        ])}
            ${renderActivityTableContent(['Section', 'Name', 'Type', 'TTL', 'Value'], rows, 'No DNS records.')}
        </section>
    `;
}

function renderPingOperationPanel(state) {
    const busy = state.pinging;

    return `
        <section class="operation-panel wa-stack wa-gap-s">
            <form id="adopted-ip-ping-form" class="operation-form wa-grid wa-gap-s">
                <wa-input label="Destination" type="text" name="destination" value="${escapeHTML(state.pingForm.destination)}" placeholder="192.168.56.1" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-ping-field="destination" ${busy ? 'disabled' : ''}></wa-input>
                <wa-number-input label="Count" name="count" value="${escapeHTML(state.pingForm.count)}" min="1" step="1" appearance="filled" size="xs" data-ping-field="count" ${busy ? 'disabled' : ''}></wa-number-input>
                <wa-number-input label="Interval (ms)" name="intervalMillis" value="${escapeHTML(state.pingForm.intervalMillis)}" min="1" step="1" appearance="filled" size="xs" data-ping-field="intervalMillis" ${busy ? 'disabled' : ''}></wa-number-input>
                <wa-number-input label="Timeout (ms)" name="timeoutMillis" value="${escapeHTML(state.pingForm.timeoutMillis)}" min="1" step="1" appearance="filled" size="xs" data-ping-field="timeoutMillis" ${busy ? 'disabled' : ''}></wa-number-input>
                <wa-number-input label="Payload (bytes)" name="payloadSize" value="${escapeHTML(state.pingForm.payloadSize)}" min="0" step="1" appearance="filled" size="xs" data-ping-field="payloadSize" ${busy ? 'disabled' : ''}></wa-number-input>
                <div class="form-actions wa-cluster wa-gap-xs wa-align-self-end">
                    <wa-button variant="brand" appearance="accent" size="xs" type="submit" ${busy ? 'loading disabled' : ''}>Ping</wa-button>
                </div>
            </form>
        </section>
    `;
}

function renderPingResultPanel(state) {
    const result = state.pingResult;
    if (!result) {
        return '';
    }
    const rows = (result.probes || []).map((probe) => `
        <tr>
            <td>${escapeHTML(String(probe.sequence))}</td>
            <td>${pill(probe.status || 'error', probe.status === 'reply' ? 'success' : 'warn')}</td>
            <td>${probe.status === 'reply' ? `${Number(probe.rttMillis || 0).toFixed(2)} ms` : '—'}</td>
            <td>${probe.status === 'reply' ? escapeHTML(String(probe.bytes || 0)) : '—'}</td>
            <td><code>${escapeHTML(probe.error || '')}</code></td>
        </tr>
    `);
    return `
        <section class="content-column ping-result wa-stack wa-gap-s">
            <header class="ping-result__header wa-split wa-gap-s">
                <h3 class="wa-heading-s">Ping result</h3>
                <span class="wa-caption-xs">${escapeHTML(`${result.received}/${result.sent} replies · ${Number(result.lossPercent || 0).toFixed(0)}% loss`)}</span>
            </header>
            ${renderInlineMeta([
        {label: 'Source', value: result.sourceIP, code: true},
        {label: 'Destination', value: result.destination, code: true},
        {label: 'Min', value: `${Number(result.minRttMillis || 0).toFixed(2)} ms`},
        {label: 'Avg', value: `${Number(result.avgRttMillis || 0).toFixed(2)} ms`},
        {label: 'Max', value: `${Number(result.maxRttMillis || 0).toFixed(2)} ms`},
    ])}
            ${renderActivityTableContent(['#', 'Status', 'RTT', 'Bytes', 'Error'], rows, 'No probes sent.')}
        </section>
    `;
}

function renderServiceField(serviceName, field, value, disabled) {
    const safeValue = String(value || '');
    const fieldName = escapeHTML(field.name);
    const serviceAttr = `data-adopted-service-name="${escapeHTML(serviceName)}"`;
    const fieldAttr = `data-adopted-service-field="${fieldName}"`;
    const required = field.required ? 'required' : '';

    if (field.type === 'select') {
        return `
            <wa-select label="${escapeHTML(field.label)}" value="${escapeHTML(safeValue)}" appearance="filled" size="xs" ${serviceAttr} ${fieldAttr} ${required} ${disabled ? 'disabled' : ''}>
                ${field.options.map((option) => `<wa-option value="${escapeHTML(option.value)}">${escapeHTML(option.label)}</wa-option>`).join('')}
            </wa-select>
        `;
    }

    if (field.type === 'directory') {
        return `
            <wa-input class="wa-span-grid" label="${escapeHTML(field.label)}" type="text" value="${escapeHTML(safeValue)}" autocomplete="off" spellcheck="false" appearance="filled" size="xs" ${serviceAttr} ${fieldAttr} ${required} ${disabled ? 'disabled' : ''}>
                <wa-button slot="end" appearance="plain" size="xs" type="button" data-choose-service-directory ${serviceAttr} ${fieldAttr} ${disabled ? 'disabled' : ''}>Browse</wa-button>
            </wa-input>
        `;
    }

    if (field.type === 'port') {
        return `
            <wa-number-input label="${escapeHTML(field.label)}" value="${escapeHTML(safeValue)}" min="1" max="65535" step="1" appearance="filled" size="xs" ${serviceAttr} ${fieldAttr} ${required} ${disabled ? 'disabled' : ''}></wa-number-input>
        `;
    }

    return `
        <wa-input label="${escapeHTML(field.label)}" type="${field.type === 'secret' ? 'password' : 'text'}" value="${escapeHTML(safeValue)}" placeholder="${escapeHTML(field.placeholder || '')}" autocomplete="off" spellcheck="false" appearance="filled" size="xs" ${field.type === 'secret' ? 'password-toggle' : ''} ${serviceAttr} ${fieldAttr} ${required} ${disabled ? 'disabled' : ''}></wa-input>
    `;
}

function renderServiceForm(definition, state) {
    const serviceName = definition.service;
    const busy = state.adoptedDetailsLoading || state.startingAdoptedService;
    const starting = state.startingAdoptedService === serviceName;
    const form = state.adoptedServiceForms[serviceName] || {};
    return `
        <form id="adopted-service-form" class="service-start-form wa-stack wa-gap-s">
            <div class="service-fields wa-grid wa-gap-s">
                ${definition.fields.map((field) => renderServiceField(serviceName, field, form[field.name], busy)).join('')}
            </div>
            <div class="form-actions wa-cluster wa-gap-xs">
                <wa-button variant="brand" appearance="accent" size="xs" type="submit" ${starting ? 'loading' : ''} ${busy ? 'disabled' : ''}>Start</wa-button>
            </div>
        </form>
    `;
}

function renderLiveServicesTable(details, state) {
    const items = [...(details?.services || [])].sort((left, right) => String(left.service || '').localeCompare(String(right.service || '')));
    if (!items.length) {
        return '';
    }

    const rows = items.map((item) => {
        return `
        <tr>
            <td>${escapeHTML(findServiceDefinition(item.service)?.label || item.service)}</td>
            <td><code>${escapeHTML(item.port || '')}</code></td>
            <td>${(item.summary || []).length ? renderInlineMeta(item.summary) : '-'}</td>
            <td>${item.lastError ? escapeHTML(item.lastError) : item.startedAt ? `<time>${escapeHTML(item.startedAt)}</time>` : '-'}</td>
            <td class="activity-actions">
                <wa-button
                    variant="danger"
                    appearance="plain"
                    size="xs"
                    type="button"
                    data-stop-adopted-service="${escapeHTML(item.service)}"
                    ${state.stoppingAdoptedService === item.service ? 'loading' : ''}
                    ${state.stoppingAdoptedService ? 'disabled' : ''}
                >
                    Stop
                </wa-button>
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
    const identityDetails = [
        {label: 'IP', value: `${current.ip}/${current.subnetPrefix || 24}`, code: true},
        {label: 'Interface', value: current.interface.Name},
        ...(current.defaultGateway ? [{label: 'Gateway', value: current.defaultGateway, code: true}] : []),
        ...(current.mac ? [{label: 'MAC', value: current.mac, code: true}] : []),
    ];

    return `
        <div class="content-column identity-workspace wa-stack wa-gap-m">
            <section class="identity-overview wa-split wa-gap-m">
                <div class="identity-overview__details wa-stack wa-gap-xs">
                    <h2 class="wa-heading-m">${escapeHTML(current.label || 'Adopted identity')}</h2>
                    ${renderInlineMeta(identityDetails)}
                </div>
                ${renderInfoCaptureControl(current, state)}
            </section>
            <section class="identity-settings wa-grid wa-gap-s">
                ${renderInfoScriptControl(state)}
                <form id="adopted-mtu-form" class="identity-setting wa-stack wa-gap-xs">
                    <wa-number-input label="MTU" name="mtu" value="${current.mtu ? escapeHTML(String(current.mtu)) : ''}" placeholder="Interface default" min="68" max="65535" step="1" appearance="filled" size="xs" ${busy ? 'disabled' : ''}></wa-number-input>
                    <div class="form-actions wa-cluster wa-gap-xs">
                        <wa-button variant="brand" appearance="accent" size="xs" type="submit" ${state.updatingAdoptedMTU ? 'loading' : ''} ${busy ? 'disabled' : ''}>Save</wa-button>
                    </div>
                </form>
            </section>
        </div>
    `;
}

function renderOperationsTab(state) {
    const selectedTab = state.selectedOperationTab === 'ping' ? 'ping' : 'dns';
    return `
        <div class="content-column operations-shell wa-stack wa-gap-s">
            <wa-select class="operations-source" label="Identity" value="${escapeHTML(state.selectedOperationSourceIP)}" appearance="filled" size="xs" data-operation-source-ip ${state.resolvingAdoptedDNS || state.pinging ? 'disabled' : ''}>
                ${renderIdentityWAOptions(state.adoptedItems)}
            </wa-select>
            <wa-tab-group class="operations-tabs" active="${selectedTab}" data-operation-tabs>
                <wa-tab panel="dns" ${selectedTab === 'dns' ? 'active' : ''}>DNS</wa-tab>
                <wa-tab panel="ping" ${selectedTab === 'ping' ? 'active' : ''}>Ping</wa-tab>
                <wa-tab-panel name="dns" ${selectedTab === 'dns' ? 'active' : ''}>
                    <div class="operations-workspace wa-stack wa-gap-s">
                        ${renderDNSOperationPanel(state)}
                        ${state.dnsError ? renderMessageBanner('DNS failed', state.dnsError) : ''}
                        ${renderDNSResultPanel(state)}
                    </div>
                </wa-tab-panel>
                <wa-tab-panel name="ping" ${selectedTab === 'ping' ? 'active' : ''}>
                    <div class="operations-workspace wa-stack wa-gap-s">
                        ${renderPingOperationPanel(state)}
                        ${state.pingError ? renderMessageBanner('Ping failed', state.pingError) : ''}
                        ${renderPingResultPanel(state)}
                    </div>
                </wa-tab-panel>
            </wa-tab-group>
        </div>
    `;
}

function renderServicesTab(details, state) {
    const selectedService = SERVICE_DEFINITIONS.some((item) => item.service === state.selectedAdoptedService)
        ? state.selectedAdoptedService
        : SERVICE_DEFINITIONS[0].service;
    const busy = state.adoptedDetailsLoading || state.startingAdoptedService;
    const liveServiceCount = details?.services?.length || 0;
    return `
        <div class="content-column services-workspace wa-stack wa-gap-l">
            <wa-select class="services-source" label="Identity" value="${escapeHTML(state.selectedServiceSourceIP)}" appearance="filled" size="xs" data-service-source-ip ${busy ? 'disabled' : ''}>
                ${renderIdentityWAOptions(state.adoptedItems)}
            </wa-select>
            <section class="services-live wa-stack wa-gap-xs">
                <div class="section-heading wa-split wa-gap-xs">
                    <h3 class="wa-heading-s">Live services</h3>
                    ${pill(liveServiceCount ? `${liveServiceCount} running` : 'None', liveServiceCount ? 'success' : 'muted')}
                </div>
                ${liveServiceCount
        ? renderLiveServicesTable(details, state)
        : '<p class="wa-caption-s">No services are running for this identity.</p>'}
            </section>
            <section class="service-launcher">
                <div class="section-heading wa-split wa-gap-xs">
                    <h3 class="wa-heading-s">Start a service</h3>
                </div>
                <wa-tab-group class="services-tabs" active="${escapeHTML(selectedService)}" data-service-tabs>
                    ${SERVICE_DEFINITIONS.map((definition) => `
                        <wa-tab panel="${escapeHTML(definition.service)}" ${definition.service === selectedService ? 'active' : ''} ${busy ? 'disabled' : ''}>${escapeHTML(definition.label)}</wa-tab>
                    `).join('')}
                    ${SERVICE_DEFINITIONS.map((definition) => `
                        <wa-tab-panel name="${escapeHTML(definition.service)}" ${definition.service === selectedService ? 'active' : ''}>
                            ${definition.service === selectedService ? renderServiceForm(definition, state) : ''}
                        </wa-tab-panel>
                    `).join('')}
                </wa-tab-group>
            </section>
        </div>
    `;
}

export function renderAdoptedIPAddressView({details, item, state}) {
    if (!item) {
        return `
            <div class="module-frame">
                ${renderModuleTopbar('')}
                ${renderStateLayout('No adopted IP selected', 'Return home and open an adopted identity.')}
            </div>
        `;
    }

    return `
        <div class="module-frame">
            ${renderModuleTopbar('')}
            <main class="single-panel-layout single-panel-layout--wide">
                ${renderCaptureStatus(details)}
                ${renderRuntimeScriptError(details)}
                ${state.adoptedMTUError ? renderMessageBanner('MTU', state.adoptedMTUError) : ''}
                ${state.adoptedScriptError ? renderMessageBanner('Scripts', state.adoptedScriptError) : ''}
                ${state.adoptedRecordingError ? renderMessageBanner('Recording', state.adoptedRecordingError) : ''}
                ${state.adoptedRecordingNotice ? renderMessageBanner('Recording', state.adoptedRecordingNotice, 'success') : ''}
                ${state.adoptedDetailsError ? renderMessageBanner('Details', state.adoptedDetailsError) : ''}
                ${renderInfoTab({details, item, state})}
            </main>
        </div>
    `;
}

export function renderOperationsModule({state}) {
    if (!state.adoptedItems.length) {
        return `
            <div class="module-frame">
                ${renderModuleTopbar('Operations')}
                ${renderStateLayout('No adopted identities', 'Adopt an identity before running operations.')}
            </div>
        `;
    }

    return `
        <div class="module-frame">
            ${renderModuleTopbar('Operations')}
            <main class="single-panel-layout single-panel-layout--wide">
                ${renderOperationsTab(state)}
            </main>
        </div>
    `;
}

export function renderServicesModule({details, state}) {
    if (!state.adoptedItems.length) {
        return `
            <div class="module-frame">
                ${renderModuleTopbar('Services')}
                ${renderStateLayout('No adopted identities', 'Adopt an identity before starting services.')}
            </div>
        `;
    }

    return `
        <div class="module-frame">
            ${renderModuleTopbar('Services')}
            <main class="single-panel-layout single-panel-layout--wide">
                ${state.adoptedServiceError ? renderMessageBanner('Service', state.adoptedServiceError) : ''}
                ${state.adoptedServiceNotice ? renderMessageBanner('Service', state.adoptedServiceNotice, 'success') : ''}
                ${state.adoptedDetailsError ? renderMessageBanner('Details', state.adoptedDetailsError) : ''}
                ${renderServicesTab(details, state)}
            </main>
        </div>
    `;
}
