import {escapeHTML, pill, renderCompactMetaLine, renderMessageBanner} from './common';

function renderStoredConfigMeta(item, compact = false) {
    const rows = [
        {label: 'Iface', value: item.interfaceName},
        {label: 'IP', value: item.ip, code: true},
        ...(item.defaultGateway ? [{label: 'Gateway', value: item.defaultGateway, code: true}] : []),
        ...(item.mtu ? [{label: 'MTU', value: String(item.mtu), code: true}] : []),
        {label: 'MAC', value: item.mac || 'Default', code: Boolean(item.mac)},
    ];

    if (compact) {
        return renderCompactMetaLine(rows);
    }

    return `
        <dl class="summary-grid">
            ${rows.map((row) => `
                <div class="summary-grid__row">
                    <dt>${escapeHTML(row.label)}</dt>
                    <dd>${row.code ? `<code>${escapeHTML(row.value)}</code>` : escapeHTML(row.value)}</dd>
                </div>
            `).join('')}
        </dl>
    `;
}

function renderStoredConfigActions(item, state, mode) {
    if (mode === 'chooser') {
        return `
            <div class="section-actions">
                <button
                    class="primary-button"
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
            <div class="section-actions section-actions--confirm">
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
        <div class="section-actions stored-config-card__actions">
            <button
                class="primary-button"
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
        <div class="config-card-list config-card-list--compact">
            ${state.storedConfigs.map((item) => `
                <article class="panel compact-list-card stored-config-card ${mode === 'manager' && state.selectedStoredConfigLabel === item.label ? 'is-selected' : ''}">
                    <div class="stored-config-card__header">
                        <strong>${escapeHTML(item.label)}</strong>
                        ${pill('Saved', 'info')}
                    </div>
                    ${renderStoredConfigMeta(item, mode === 'chooser')}
                    ${renderStoredConfigActions(item, state, mode)}
                </article>
            `).join('')}
        </div>
    `;
}

export {renderStoredConfigList};
