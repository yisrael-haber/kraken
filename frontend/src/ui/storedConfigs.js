import {escapeHTML} from './common';

function renderStoredIdentityMeta(item) {
    return `
        <div class="stored-identity-meta">
            <code>${escapeHTML(item.ip)}/${escapeHTML(item.subnetPrefix || 24)}</code>
            <span>${escapeHTML(item.interfaceName)}</span>
        </div>
    `;
}

function renderStoredConfigActions(item, state) {
    if (state.pendingCopyStoredConfig === item.label) {
        return `
            <form id="stored-config-copy-form" class="library-row__actions">
                <wa-input
                    class="stored-identity-copy-input"
                    type="text"
                    name="label"
                    value="${escapeHTML(state.storedConfigCopyLabel)}"
                    placeholder="Copy as"
                    aria-label="New identity label"
                    autocomplete="off"
                    spellcheck="false"
                    data-stored-config-copy-label
                    autofocus
                    size="xs"
                    ${state.copyingStoredConfig ? 'disabled' : ''}
                ></wa-input>
                <wa-button variant="brand" appearance="plain" size="xs" type="submit" ${state.copyingStoredConfig ? 'loading' : ''} ${state.copyingStoredConfig ? 'disabled' : ''}>
                    Create copy
                </wa-button>
                <wa-button
                    appearance="plain"
                    size="xs"
                    type="button"
                    data-cancel-copy-stored-config
                    ${state.copyingStoredConfig ? 'disabled' : ''}
                >
                    Cancel
                </wa-button>
            </form>
        `;
    }

    if (state.pendingDeleteStoredConfig === item.label) {
        return `
            <div class="library-row__actions inline-confirmation">
                <span class="inline-confirm">Delete this identity?</span>
                <wa-button
                    variant="danger"
                    appearance="plain"
                    size="xs"
                    type="button"
                    data-confirm-delete-stored-config="${escapeHTML(item.label)}"
                    ${state.deletingStoredConfigLabel === item.label ? 'loading' : ''}
                    ${state.deletingStoredConfigLabel ? 'disabled' : ''}
                >
                    Delete
                </wa-button>
                <wa-button
                    appearance="plain"
                    size="xs"
                    type="button"
                    data-cancel-delete-stored-config
                    ${state.deletingStoredConfigLabel ? 'disabled' : ''}
                >
                    Cancel
                </wa-button>
            </div>
        `;
    }

    const busy = state.adoptingStoredLabel || state.copyingStoredConfig || state.deletingStoredConfigLabel || state.savingStoredConfig;

    return `
        <div class="library-row__actions">
            <wa-button
                variant="brand"
                appearance="outlined"
                size="xs"
                type="button"
                data-adopt-stored-config="${escapeHTML(item.label)}"
                ${state.adoptingStoredLabel === item.label ? 'loading' : ''}
                ${busy ? 'disabled' : ''}
            >
                Adopt
            </wa-button>
            <wa-button
                appearance="plain"
                size="xs"
                type="button"
                data-edit-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
                title="Edit identity"
            >
                Edit
            </wa-button>
            <wa-button
                appearance="plain"
                size="xs"
                type="button"
                data-stage-copy-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
                title="Copy identity"
            >
                <wa-icon library="system" name="copy" variant="regular" label="Copy ${escapeHTML(item.label)}"></wa-icon>
            </wa-button>
            <wa-button
                appearance="plain"
                size="xs"
                type="button"
                data-stage-delete-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
                title="Delete identity"
            >
                <wa-icon library="system" name="xmark" label="Delete ${escapeHTML(item.label)}"></wa-icon>
            </wa-button>
        </div>
    `;
}

function renderStoredConfigList(state) {
    if (state.storedConfigsLoading && !state.storedConfigs.length) {
        return '<div class="empty-state">Loading saved identities.</div>';
    }
    if (!state.storedConfigs.length) {
        return '<div class="empty-state">No saved identities.</div>';
    }

    return state.storedConfigs.map((item) => `
        <article class="library-row stored-identity-row ${state.selectedStoredConfigLabel === item.label ? 'is-selected' : ''}">
            <div class="stored-identity-row__summary">
                <strong>${escapeHTML(item.label)}</strong>
                ${renderStoredIdentityMeta(item)}
            </div>
            ${renderStoredConfigActions(item, state)}
        </article>
    `).join('');
}

export {renderStoredConfigList};
