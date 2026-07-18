import {escapeHTML, renderMessageBanner} from './common';

function renderStoredIdentityMeta(item) {
    return `
        <div class="stored-identity-meta">
            <code>${escapeHTML(item.ip)}/${escapeHTML(item.subnetPrefix || 24)}</code>
            <span>${escapeHTML(item.interfaceName)}</span>
        </div>
    `;
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

    if (state.pendingCopyStoredConfig === item.label) {
        return `
            <form id="stored-config-copy-form" class="stored-identity-row__actions stored-identity-row__actions--copy">
                <input
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
                    ${state.copyingStoredConfig ? 'disabled' : ''}
                />
                <button class="adopt-submit" type="submit" ${state.copyingStoredConfig ? 'disabled' : ''}>
                    ${state.copyingStoredConfig ? 'Copying...' : 'Create copy'}
                </button>
                <button
                    class="ghost-button"
                    type="button"
                    data-cancel-copy-stored-config
                    ${state.copyingStoredConfig ? 'disabled' : ''}
                >
                    Cancel
                </button>
            </form>
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

    const busy = state.adoptingStoredLabel || state.copyingStoredConfig || state.deletingStoredConfigLabel || state.savingStoredConfig;

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
                aria-label="Edit ${escapeHTML(item.label)}"
                title="Edit identity"
            >
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 20 4.2-1 10.6-10.6-3.2-3.2L5 15.8 4 20Zm9.8-13 3.2 3.2" /></svg>
            </button>
            <button
                class="ghost-button"
                type="button"
                data-stage-copy-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
                aria-label="Copy ${escapeHTML(item.label)}"
                title="Copy identity"
            >
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8h11v11H8zM5 16H4V5h11v1" /></svg>
            </button>
            <button
                class="ghost-button stored-identity-delete"
                type="button"
                data-stage-delete-stored-config="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
                aria-label="Delete ${escapeHTML(item.label)}"
                title="Delete identity"
            >
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3m3 0-1 13H7L6 7m4 4v5m4-5v5" /></svg>
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
                    ${renderStoredConfigActions(item, state, mode)}
                    ${renderStoredIdentityMeta(item)}
                </article>
            `).join('')}
        </div>
    `;
}

export {renderStoredConfigList};
