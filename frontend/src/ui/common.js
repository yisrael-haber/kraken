export function escapeHTML(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

export function pill(label, tone = 'muted') {
    return `<span class="pill tone-${tone}">${escapeHTML(label)}</span>`;
}

export function renderMessageBanner(title, message) {
    return `
        <section class="panel message-banner">
            <strong>${escapeHTML(title)}</strong>
            <p>${escapeHTML(message)}</p>
        </section>
    `;
}

export function renderStateLayout(layoutClass, title, message) {
    return `
        <main class="${layoutClass}">
            <section class="panel state-panel">
                <h2>${escapeHTML(title)}</h2>
                <p>${escapeHTML(message)}</p>
            </section>
        </main>
    `;
}

export function renderInterfaceOptions(items, selectedName, emptyText) {
    if (!items.length) {
        return `<option value="">${escapeHTML(emptyText)}</option>`;
    }

    return items.map((name) => `
        <option value="${escapeHTML(name)}" ${name === selectedName ? 'selected' : ''}>
            ${escapeHTML(name)}
        </option>
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

export function renderIdentityFields({form, interfaceOptions, disabled, dataAttribute, fieldClassPrefix, order}) {
    const disabledAttribute = disabled ? 'disabled' : '';

    return order.map((name) => {
        const field = identityFieldDefinitions[name];
        const classes = `adopt-control ${fieldClassPrefix}--${field.area}`;
        const data = `${dataAttribute}="${name}"`;
        if (field.select) {
            return `
                <label class="${classes}">
                    <span>${field.label}</span>
                    <select name="${name}" ${data} ${disabledAttribute}>
                        ${interfaceOptions}
                    </select>
                </label>
            `;
        }

        return `
            <label class="${classes}">
                <span>${field.label}</span>
                <input
                    type="text"
                    name="${name}"
                    value="${escapeHTML(form[name] || '')}"
                    placeholder="${field.placeholder || ''}"
                    autocomplete="off"
                    spellcheck="false"
                    ${field.numeric ? 'inputmode="numeric"' : ''}
                    ${data}
                    ${disabledAttribute}
                />
            </label>
        `;
    }).join('');
}

export function renderModuleTopbar(title) {
    if (!title) {
        return `
            <header class="module-topbar module-topbar--back-only">
                <button class="ghost-button ghost-button--back" type="button" data-go-home>Back</button>
            </header>
        `;
    }

    return `
        <header class="module-topbar">
            <button class="ghost-button ghost-button--back" type="button" data-go-home>Back</button>
            <div class="module-topbar__copy">
                <h1>${escapeHTML(title)}</h1>
            </div>
        </header>
    `;
}
