import {
    escapeHTML,
    pill,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';

function renderStoredConfigSummary(item) {
    const rows = [
        ['Iface', item.interfaceName, false],
        ['IP', item.ip, true],
        ...(item.defaultGateway ? [['Gateway', item.defaultGateway, true]] : []),
        ['MAC', item.mac || 'Default', Boolean(item.mac)],
    ];

    return `
        <dl class="summary-grid">
            ${rows.map(([label, value, code]) => `
                <div class="summary-grid__row">
                    <dt>${escapeHTML(label)}</dt>
                    <dd>${code ? `<code>${escapeHTML(value)}</code>` : escapeHTML(value)}</dd>
                </div>
            `).join('')}
        </dl>
    `;
}

function renderStoredConfigList(state) {
    if (state.storedConfigsLoading && !state.storedConfigs.length) {
        return '<div class="empty-state">Loading stored configurations...</div>';
    }

    if (!state.storedConfigs.length) {
        return '<div class="empty-state">No stored configurations yet.</div>';
    }

    return `
        <div class="config-card-list config-card-list--compact">
            ${state.storedConfigs.map((item) => {
        const isSelected = state.selectedStoredConfigLabel === item.label;
        const isPendingDelete = state.pendingDeleteStoredConfig === item.label;

        return `
                <article class="panel compact-list-card stored-config-card ${isSelected ? 'is-selected' : ''}">
                    <div class="stored-config-card__header">
                        <strong>${escapeHTML(item.label)}</strong>
                        ${pill('Stored', 'info')}
                    </div>

                    ${renderStoredConfigSummary(item)}

                    ${isPendingDelete ? `
                        <div class="section-actions section-actions--confirm">
                            <span class="inline-confirm">Delete this configuration?</span>
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
                    ` : `
                        <div class="section-actions stored-config-card__actions">
                            <button
                                class="primary-button"
                                type="button"
                                data-adopt-stored-config="${escapeHTML(item.label)}"
                                ${(state.adoptingStoredLabel || state.deletingStoredConfigLabel || state.savingStoredConfig) ? 'disabled' : ''}
                            >
                                ${state.adoptingStoredLabel === item.label ? 'Adopting...' : 'Adopt'}
                            </button>
                            <button
                                class="ghost-button"
                                type="button"
                                data-edit-stored-config="${escapeHTML(item.label)}"
                                ${(state.adoptingStoredLabel || state.deletingStoredConfigLabel || state.savingStoredConfig) ? 'disabled' : ''}
                            >
                                Edit
                            </button>
                            <button
                                class="ghost-button"
                                type="button"
                                data-stage-delete-stored-config="${escapeHTML(item.label)}"
                                ${(state.adoptingStoredLabel || state.deletingStoredConfigLabel || state.savingStoredConfig) ? 'disabled' : ''}
                            >
                                Remove
                            </button>
                        </div>
                    `}
                </article>
            `;
    }).join('')}
        </div>
    `;
}

function renderStoredConfigEditor(interfaces, state) {
    const busy = state.savingStoredConfig || state.deletingStoredConfigLabel || state.adoptingStoredLabel;
    const isEditing = Boolean(state.selectedStoredConfigLabel);
    const interfaceOptions = renderInterfaceOptions(
        interfaces,
        state.storedConfigEditor.interfaceName,
        'No adoptable interfaces available',
    );

    return `
        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <span class="eyebrow">Editor</span>
                    <h3>${isEditing ? escapeHTML(state.selectedStoredConfigLabel) : 'New configuration'}</h3>
                    <p>${isEditing ? 'Update this stored identity.' : 'Create a reusable stored identity.'}</p>
                </div>
                <button class="ghost-button" type="button" data-new-stored-config ${busy ? 'disabled' : ''}>
                    New
                </button>
            </div>

            <form id="stored-adoption-config-form" class="form-stack form-stack--compact">
                <div class="compact-form-grid">
                    <label class="form-field">
                        <span>Label</span>
                        <input
                            type="text"
                            name="label"
                            value="${escapeHTML(state.storedConfigEditor.label)}"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="label"
                            ${(busy || isEditing) ? 'disabled' : ''}
                        />
                        <small class="field-note">Stored name.</small>
                    </label>

                    <label class="form-field">
                        <span>IP</span>
                        <input
                            type="text"
                            name="ip"
                            value="${escapeHTML(state.storedConfigEditor.ip)}"
                            placeholder="192.168.56.50"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="ip"
                            ${busy ? 'disabled' : ''}
                        />
                        <small class="field-note field-note--placeholder" aria-hidden="true">&nbsp;</small>
                    </label>

                    <label class="form-field">
                        <span>Gateway</span>
                        <input
                            type="text"
                            name="defaultGateway"
                            value="${escapeHTML(state.storedConfigEditor.defaultGateway || '')}"
                            placeholder="Optional"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="defaultGateway"
                            ${busy ? 'disabled' : ''}
                        />
                        <small class="field-note">Optional next hop.</small>
                    </label>

                    <label class="form-field">
                        <span>MAC</span>
                        <input
                            type="text"
                            name="mac"
                            value="${escapeHTML(state.storedConfigEditor.mac)}"
                            placeholder="Optional"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="mac"
                            ${busy ? 'disabled' : ''}
                        />
                        <small class="field-note">Optional.</small>
                    </label>

                    <label class="form-field">
                        <span>Interface</span>
                        <select
                            name="interfaceName"
                            data-stored-config-field="interfaceName"
                            ${busy ? 'disabled' : ''}
                        >
                            ${interfaceOptions}
                        </select>
                        <small class="field-note">Adoptable only.</small>
                    </label>
                </div>

                <div class="form-actions form-actions--compact">
                    <button class="primary-button" type="submit" ${busy || !interfaces.length ? 'disabled' : ''}>
                        ${state.savingStoredConfig ? 'Saving...' : 'Save'}
                    </button>
                    <button class="ghost-button" type="button" data-new-stored-config ${busy ? 'disabled' : ''}>
                        Reset
                    </button>
                </div>
            </form>
        </section>
    `;
}

export function renderStoredAdoptionsModule({interfaces, state}) {
    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Stored Adoptions', 'Manage persistent stored identities.')}

            <main class="single-panel-layout single-panel-layout--wide">
                ${state.storedConfigsError ? renderMessageBanner('Stored configuration notice', state.storedConfigsError) : ''}
                ${state.storedConfigNotice ? renderMessageBanner('Stored configuration saved', state.storedConfigNotice) : ''}

                <section class="override-layout config-management-layout">
                    <section class="panel section-panel section-panel--compact">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Library</span>
                                <h3>Stored configurations</h3>
                                <p>Reusable identities for fast adoption.</p>
                            </div>
                        </div>

                        ${renderStoredConfigList(state)}
                    </section>

                    ${renderStoredConfigEditor(interfaces, state)}
                </section>
            </main>
        </div>
    `;
}
