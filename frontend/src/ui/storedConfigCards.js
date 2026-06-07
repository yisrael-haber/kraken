import {escapeHTML, renderMessageBanner} from './common';

function renderStoredIdentityMeta(items) {
    return `
        <div class="stored-identity-meta">
            ${items.map((item) => `
                <span class="stored-identity-meta__item">
                    <span class="stored-identity-meta__label">${escapeHTML(item.label)}</span>
                    <span class="stored-identity-meta__value">
                        ${item.code ? `<code>${escapeHTML(item.value)}</code>` : `<span>${escapeHTML(item.value)}</span>`}
                    </span>
                </span>
            `).join('')}
        </div>
    `;
}

function storedIdentityMeta(item) {
    return [
        {label: 'IF', value: item.interfaceName},
        {label: 'IP', value: `${item.ip}/${item.subnetPrefix || 24}`, code: true},
        ...(item.defaultGateway ? [{label: 'GW', value: item.defaultGateway, code: true}] : []),
        {label: 'MAC', value: item.mac || 'Default', code: Boolean(item.mac)},
        {label: 'MTU', value: item.mtu ? String(item.mtu) : 'Iface', code: Boolean(item.mtu)},
    ];
}

function renderStoredConfigActions(item, state, mode) {
    if (mode === 'chooser') {
        return `
            <div class="stored-identity-row__actions">
                <button
                    class="adopt-submit"
                    type="button"
                    data-adopt-stored-config="${escapeHTML(item.label)}"
                    ${state.adoptingStoredLabel ? 'disabled' : ''}
                >
                    ${state.adoptingStoredLabel === item.label ? 'Adopting...' : 'Adopt'}
                </button>
            </div>
        `;
    }

    if (state.pendingDeleteStoredConfig === item.label) {
        return `
            <div class="stored-identity-row__actions stored-identity-row__actions--confirm">
                <span class="inline-confirm">Delete this identity?</span>
                <button
                    class="danger-button"
                    type="button"
                    data-confirm-delete-stored-config="${escapeHTML(item.label)}"
                    ${state.deletingStoredConfigLabel ? 'disabled' : ''}
                >
                    ${state.deletingStoredConfigLabel === item.label ? 'Deleting...' : 'Delete'}
                </button>
                <button
                    class="ghost-button"
                    type="button"
                    data-cancel-delete-stored-config
                    ${state.deletingStoredConfigLabel ? 'disabled' : ''}
                >
                    Cancel
                </button>
            </div>
        `;
    }

    const busy = state.adoptingStoredLabel || state.deletingStoredConfigLabel || state.savingStoredConfig;

    return `
        <div class="stored-identity-row__actions">
            <button
                class="adopt-submit"
                type="button"
                data-adopt-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
            >
                ${state.adoptingStoredLabel === item.label ? 'Adopting...' : 'Adopt'}
            </button>
            <button
                class="ghost-button"
                type="button"
                data-edit-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
            >
                Edit
            </button>
            <button
                class="ghost-button"
                type="button"
                data-stage-delete-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
            >
                Remove
            </button>
        </div>
    `;
}

function renderStoredConfigList(state, mode) {
    if (state.storedConfigsLoading && !state.storedConfigs.length) {
        return '<div class="empty-state">Loading saved identities.</div>';
    }
    if (mode === 'chooser' && state.storedConfigsError) {
        return renderMessageBanner('Saved identities', state.storedConfigsError);
    }
    if (!state.storedConfigs.length) {
        return '<div class="empty-state">No saved identities.</div>';
    }

    return `
        <div class="stored-identity-list">
            ${state.storedConfigs.map((item) => `
                <article class="stored-identity-row stored-identity-row--${escapeHTML(mode)} ${mode === 'manager' && state.selectedStoredConfigLabel === item.label ? 'is-selected' : ''}">
                    <div class="stored-identity-row__label">
                        <strong>${escapeHTML(item.label)}</strong>
                    </div>
                    ${renderStoredIdentityMeta(storedIdentityMeta(item))}
                    ${renderStoredConfigActions(item, state, mode)}
                </article>
            `).join('')}
        </div>
    `;
}

export {renderStoredConfigList};
