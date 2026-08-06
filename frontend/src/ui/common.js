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
            <p>${escapeHTML(message)}</p>
        </wa-callout>
    `;
}

export function renderStateLayout(title, message) {
    return `
        <main class="single-panel-layout">
            <section class="state-panel">
                <h2>${escapeHTML(title)}</h2>
                <p>${escapeHTML(message)}</p>
            </section>
        </main>
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
    label: {label: 'Label', area: 'label'},
    interfaceName: {label: 'Interface', area: 'interface', select: true},
    ip: {label: 'IP', area: 'ip', placeholder: '192.168.56.50'},
    subnetPrefix: {label: 'Prefix', area: 'prefix', placeholder: '24', numeric: true},
    defaultGateway: {label: 'Gateway', area: 'gateway', placeholder: 'Optional'},
    mac: {label: 'MAC', area: 'mac', placeholder: 'Optional'},
    mtu: {label: 'MTU', area: 'mtu', placeholder: 'Iface', numeric: true},
};

export function renderIdentityFields({form, interfaceOptions, disabled, disabledFields = [], dataAttribute, order}) {
    return order.map((name) => {
        const field = identityFieldDefinitions[name];
        const classes = `identity-field identity-field--${field.area}`;
        const data = `${dataAttribute}="${name}"`;
        const disabledAttribute = disabled || disabledFields.includes(name) ? 'disabled' : '';
        if (field.select) {
            return `
                <wa-select
                    class="${classes}"
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
                class="${classes}"
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

export function renderModuleTopbar(title) {
    if (!title) {
        return `
            <header class="module-topbar module-topbar--back-only">
                <wa-button appearance="plain" size="xs" type="button" data-go-home>Back</wa-button>
            </header>
        `;
    }

    return `
        <header class="module-topbar">
            <wa-button appearance="plain" size="xs" type="button" data-go-home>Back</wa-button>
            <h1>${escapeHTML(title)}</h1>
        </header>
    `;
}
