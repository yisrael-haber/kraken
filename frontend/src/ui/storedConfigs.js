import {escapeHTML} from './common';

function renderStoredIdentityMeta(item) {
    return `
        <div class="stored-identity-meta wa-cluster wa-gap-xs wa-caption-xs">
            <code>${escapeHTML(item.ip)}/${escapeHTML(item.subnetPrefix || 24)}</code>
            <span>${escapeHTML(item.interfaceName)}</span>
        </div>
    `;
}

function renderStoredConfigActions(item, state) {
    if (state.pendingCopyStoredConfig === item.label) {
        return `
            <form id="stored-config-copy-form" class="library-row__actions wa-cluster wa-gap-2xs">
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
                    appearance="filled"
                    size="xs"
                    ${state.copyingStoredConfig ? 'disabled' : ''}
                ></wa-input>
                <wa-button variant="brand" appearance="accent" size="xs" type="submit" ${state.copyingStoredConfig ? 'loading' : ''} ${state.copyingStoredConfig ? 'disabled' : ''}>
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
            <div class="library-row__actions inline-confirmation wa-cluster wa-gap-2xs">
                <span class="inline-confirm wa-caption-xs">Delete this identity?</span>
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
        <div class="library-row__actions wa-cluster wa-gap-2xs">
            <wa-button
                variant="brand"
                appearance="accent"
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
        return '<div class="empty-state wa-caption-s">Loading saved identities.</div>';
    }
    if (!state.storedConfigs.length) {
        return '<div class="empty-state wa-caption-s">No saved identities.</div>';
    }

    return state.storedConfigs.map((item) => `
        <article class="library-row stored-identity-row ${state.selectedStoredConfigLabel === item.label ? 'is-selected' : ''}">
            <div class="stored-identity-row__summary wa-stack wa-gap-2xs">
                <strong class="wa-text-truncate">${escapeHTML(item.label)}</strong>
                ${renderStoredIdentityMeta(item)}
            </div>
            ${renderStoredConfigActions(item, state)}
        </article>
    `).join('');
}

export {renderStoredConfigList};
