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
