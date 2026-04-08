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

export function tag(label, tone = 'muted') {
    return `<span class="tag tone-${tone}">${escapeHTML(label)}</span>`;
}

function osFlagTone(flag) {
    switch (flag) {
    case 'up':
    case 'running':
        return 'success';
    case 'broadcast':
    case 'multicast':
        return 'info';
    case 'loopback':
        return 'warn';
    default:
        return 'muted';
    }
}

export function interfaceBadges(item) {
    const items = [];

    items.push(item.isUp ? pill('Up', 'success') : pill('Down'));

    if (item.captureOnly) {
        items.push(pill('Capture only', 'warn'));
    }
    if (item.isLoopback) {
        items.push(pill('Loopback', 'warn'));
    }
    if (item.captureVisible && !item.captureOnly) {
        items.push(pill('pcap visible', 'info'));
    }

    return items.join('');
}

export function previewAddresses(item) {
    const addresses = item.systemAddresses?.length ? item.systemAddresses : item.captureAddresses;
    if (!addresses?.length) {
        return 'No addresses reported';
    }

    return addresses.slice(0, 2).map((address) => escapeHTML(address.address)).join(' · ');
}

export function renderInterfaceTags(item) {
    const tags = (item.osFlags ?? []).map((flag) => tag(flag, osFlagTone(flag)));

    if (!tags.length) {
        return '';
    }

    return `<div class="interface-item__tags">${tags.join('')}</div>`;
}

export function renderMessageBanner(title, message) {
    return `
        <section class="panel message-banner">
            <strong>${escapeHTML(title)}</strong>
            <p>${escapeHTML(message)}</p>
        </section>
    `;
}

export function renderStateLayout(layoutClass, title, message, tone = '') {
    const toneClass = tone ? ` state-panel--${tone}` : '';

    return `
        <main class="${layoutClass}">
            <section class="panel state-panel${toneClass}">
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

    return items.map((item) => `
        <option value="${escapeHTML(item.name)}" ${item.name === selectedName ? 'selected' : ''}>
            ${escapeHTML(item.name)}
        </option>
    `).join('');
}

export function renderModuleTopbar(title, detail) {
    return `
        <header class="module-topbar panel">
            <button class="ghost-button ghost-button--back" type="button" data-go-home>Back</button>
            <div class="module-topbar__copy">
                <span class="eyebrow">Module</span>
                <h1>${escapeHTML(title)}</h1>
                <p>${escapeHTML(detail)}</p>
            </div>
        </header>
    `;
}

export function renderCompactMetaLine(items) {
    return `
        <div class="compact-meta-line">
            ${items.map((item) => `
                <span class="compact-meta-line__item">
                    <span class="compact-meta-line__label">${escapeHTML(item.label)}</span>
                    <span class="compact-meta-line__value">
                        ${item.code ? `<code>${escapeHTML(item.value)}</code>` : `<span>${escapeHTML(item.value)}</span>`}
                    </span>
                </span>
            `).join('')}
        </div>
    `;
}

export function renderDataList(items, emptyText) {
    if (!items?.length) {
        return `<div class="empty-state">${escapeHTML(emptyText)}</div>`;
    }

    return `
        <div class="data-list">
            ${items.map((item) => `
                <article class="data-row">
                    <div class="data-row__main">
                        <strong>${escapeHTML(item.address)}</strong>
                        <span>${escapeHTML(item.family || 'Address')}</span>
                    </div>
                    <dl class="data-row__meta">
                        ${item.netmask ? `<div><dt>Netmask</dt><dd>${escapeHTML(item.netmask)}</dd></div>` : ''}
                        ${item.broadcast ? `<div><dt>Broadcast</dt><dd>${escapeHTML(item.broadcast)}</dd></div>` : ''}
                        ${item.peer ? `<div><dt>Peer</dt><dd>${escapeHTML(item.peer)}</dd></div>` : ''}
                    </dl>
                </article>
            `).join('')}
        </div>
    `;
}

export function renderFlagList(items, emptyText, toneForItem = () => 'muted') {
    if (!items?.length) {
        return `<div class="empty-state">${escapeHTML(emptyText)}</div>`;
    }

    return `
        <div class="tag-list">
            ${items.map((item) => tag(item, toneForItem(item))).join('')}
        </div>
    `;
}

export function renderOverviewRows(item) {
    const rows = [
        ['Description', item.description || 'No pcap description reported'],
        ['Index', item.captureOnly ? 'Capture-only device' : item.index || 'Unavailable'],
        ['MTU', item.captureOnly ? 'Unavailable' : item.mtu || 'Unavailable'],
        ['MAC', item.hardwareAddr || 'Unavailable'],
        ['System addresses', item.systemAddresses?.length || 0],
        ['Capture addresses', item.captureAddresses?.length || 0],
        ['Raw pcap flags', item.captureVisible ? `0x${Number(item.rawCaptureFlags || 0).toString(16).padStart(8, '0')}` : 'Unavailable'],
    ];

    return `
        <dl class="meta-list">
            ${rows.map(([label, value]) => `
                <div class="meta-list__row">
                    <dt>${escapeHTML(label)}</dt>
                    <dd>${escapeHTML(value)}</dd>
                </div>
            `).join('')}
        </dl>
    `;
}
