export function escapeHTML(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

export function pill(label, tone = 'muted') {
    const variant = tone === 'warn' ? 'warning' : tone === 'muted' ? 'neutral' : tone;
    return `<wa-badge variant="${variant}" appearance="filled-outlined" pill>${escapeHTML(label)}</wa-badge>`;
}

export function renderMessageBanner(title, message, variant = 'danger') {
    return `
        <wa-callout class="message-banner" variant="${variant}" appearance="filled-outlined" size="s">
            <strong>${escapeHTML(title)}</strong>
            <p class="wa-caption-s">${escapeHTML(message)}</p>
        </wa-callout>
    `;
}

export function renderStateLayout(title, message) {
    return `
        <section class="single-panel-layout wa-stack wa-gap-s">
            <section class="state-panel wa-stack wa-gap-2xs wa-align-items-center wa-justify-content-center">
                <h2 class="wa-heading-m">${escapeHTML(title)}</h2>
                <p class="wa-caption-s">${escapeHTML(message)}</p>
            </section>
        </section>
    `;
}

export function renderInterfaceOptions(items, emptyText) {
    if (!items.length) {
        return `<wa-option value="">${escapeHTML(emptyText)}</wa-option>`;
    }

    return items.map((name) => `
        <wa-option value="${escapeHTML(name)}">
            ${escapeHTML(name)}
        </wa-option>
    `).join('');
}

const identityFieldDefinitions = {
    label: {label: 'Label'},
    interfaceName: {label: 'Interface', select: true},
    ip: {label: 'IP', placeholder: '192.168.56.50'},
    subnetPrefix: {label: 'Prefix', placeholder: '24', numeric: true},
    defaultGateway: {label: 'Gateway', placeholder: 'Optional'},
    mac: {label: 'MAC', placeholder: 'Optional'},
    mtu: {label: 'MTU', placeholder: 'Iface', numeric: true},
};

export function renderIdentityFields({form, interfaceOptions, disabled, disabledFields = [], dataAttribute, order}) {
    return order.map((name) => {
        const field = identityFieldDefinitions[name];
        const data = `${dataAttribute}="${name}"`;
        const disabledAttribute = disabled || disabledFields.includes(name) ? 'disabled' : '';
        if (field.select) {
            return `
                <wa-select
                    class="identity-field"
                    label="${field.label}"
                    name="${name}"
                    value="${escapeHTML(form[name] || '')}"
                    appearance="filled"
                    size="xs"
                    ${data}
                    ${disabledAttribute}
                >
                    ${interfaceOptions}
                </wa-select>
            `;
        }

        return `
            <wa-input
                class="identity-field"
                label="${field.label}"
                type="text"
                name="${name}"
                value="${escapeHTML(form[name] || '')}"
                placeholder="${field.placeholder || ''}"
                autocomplete="off"
                spellcheck="false"
                appearance="filled"
                size="xs"
                ${field.numeric ? 'inputmode="numeric"' : ''}
                ${data}
                ${disabledAttribute}
            ></wa-input>
        `;
    }).join('');
}

export function renderModuleTopbar(title, {backToIdentities = false} = {}) {
    return `
        <header class="wa-cluster wa-gap-xs">
            ${backToIdentities ? `
                <wa-button appearance="plain" size="xs" type="button" data-open-module="identities" title="Back to identities" aria-label="Back to identities">
                    <wa-icon library="system" name="chevron-left"></wa-icon>
                </wa-button>
            ` : ''}
            ${title ? `<h1 class="wa-heading-l">${escapeHTML(title)}</h1>` : ''}
        </header>
    `;
}
