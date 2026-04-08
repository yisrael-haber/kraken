import {
    escapeHTML,
    pill,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';

function countEnabledFields(editor, section) {
    return section.fields.filter((field) => editor.layers?.[section.layer]?.[field.name]?.enabled).length;
}

function summarizeOverride(override) {
    const layers = Object.entries(override.layers || {})
        .filter(([, fields]) => fields && Object.keys(fields).length)
        .map(([layer]) => layer);

    return layers.length ? layers.join(' · ') : 'No active layers';
}

function renderStoredOverrideList(state) {
    if (state.storedOverridesLoading && !state.storedOverrides.length) {
        return '<div class="empty-state">Loading stored packet overrides...</div>';
    }

    if (!state.storedOverrides.length) {
        return '<div class="empty-state">No packet overrides yet.</div>';
    }

    return `
        <div class="config-card-list config-card-list--compact">
            ${state.storedOverrides.map((item) => {
        const isSelected = state.selectedStoredOverrideName === item.name;
        const isPendingDelete = state.pendingDeleteStoredOverride === item.name;

        return `
                    <article class="panel compact-list-card override-card ${isSelected ? 'is-selected' : ''}">
                        <div class="compact-list-card__row">
                            <div>
                                <strong>${escapeHTML(item.name)}</strong>
                                <p>${escapeHTML(summarizeOverride(item))}</p>
                            </div>
                            ${pill('Stored', 'info')}
                        </div>

                        ${isPendingDelete ? `
                            <div class="section-actions section-actions--confirm">
                                <span class="inline-confirm">Delete this override?</span>
                                <button
                                    class="danger-button"
                                    type="button"
                                    data-confirm-delete-stored-override="${escapeHTML(item.name)}"
                                    ${state.deletingStoredOverrideName ? 'disabled' : ''}
                                >
                                    ${state.deletingStoredOverrideName === item.name ? 'Deleting...' : 'Delete'}
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-cancel-delete-stored-override
                                    ${state.deletingStoredOverrideName ? 'disabled' : ''}
                                >
                                    Cancel
                                </button>
                            </div>
                        ` : `
                            <div class="section-actions">
                                <button
                                    class="primary-button"
                                    type="button"
                                    data-edit-stored-override="${escapeHTML(item.name)}"
                                    ${(state.savingStoredOverride || state.deletingStoredOverrideName) ? 'disabled' : ''}
                                >
                                    Edit
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-stage-delete-stored-override="${escapeHTML(item.name)}"
                                    ${(state.savingStoredOverride || state.deletingStoredOverrideName) ? 'disabled' : ''}
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

function renderLayerSection(section, editor, busy) {
    const enabledCount = countEnabledFields(editor, section);

    return `
        <details class="panel fold-panel layer-panel" ${enabledCount ? 'open' : ''}>
            <summary class="fold-panel__summary">
                <div>
                    <span class="eyebrow">Layer</span>
                    <strong>${escapeHTML(section.layer)}</strong>
                </div>
                <span class="fold-panel__count">${enabledCount ? `${enabledCount} enabled` : 'Collapsed'}</span>
            </summary>

            <div class="fold-panel__body">
                <div class="override-field-list">
                    ${section.fields.map((field) => {
        const current = editor.layers?.[section.layer]?.[field.name] ?? {enabled: false, value: ''};
        const fieldId = `override-${section.layer}-${field.name}`;
        const inputValue = current.value ?? '';

        let control = `
                                <input
                                    id="${escapeHTML(fieldId)}"
                                    type="text"
                                    value="${escapeHTML(inputValue)}"
                                    placeholder="${escapeHTML(field.placeholder || '')}"
                                    autocomplete="off"
                                    spellcheck="false"
                                    data-override-layer="${escapeHTML(section.layer)}"
                                    data-override-field="${escapeHTML(field.name)}"
                                    data-override-control="value"
                                    ${busy ? 'disabled' : ''}
                                />
                            `;

        if (field.type === 'number') {
            control = `
                                <input
                                    id="${escapeHTML(fieldId)}"
                                    type="number"
                                    value="${escapeHTML(inputValue)}"
                                    placeholder="${escapeHTML(field.placeholder || '')}"
                                    inputmode="numeric"
                                    data-override-layer="${escapeHTML(section.layer)}"
                                    data-override-field="${escapeHTML(field.name)}"
                                    data-override-control="value"
                                    ${busy ? 'disabled' : ''}
                                />
                            `;
        } else if (field.type === 'select') {
            control = `
                                <select
                                    id="${escapeHTML(fieldId)}"
                                    data-override-layer="${escapeHTML(section.layer)}"
                                    data-override-field="${escapeHTML(field.name)}"
                                    data-override-control="value"
                                    ${busy ? 'disabled' : ''}
                                >
                                    ${field.options.map((option) => `
                                        <option value="${escapeHTML(option)}" ${inputValue === option ? 'selected' : ''}>${escapeHTML(option)}</option>
                                    `).join('')}
                                </select>
                            `;
        }

        return `
                            <label class="override-field-row">
                                <span class="override-field-row__toggle">
                                    <input
                                        type="checkbox"
                                        data-override-layer="${escapeHTML(section.layer)}"
                                        data-override-field="${escapeHTML(field.name)}"
                                        data-override-control="toggle"
                                        ${current.enabled ? 'checked' : ''}
                                        ${busy ? 'disabled' : ''}
                                    />
                                    <span>${escapeHTML(field.name)}</span>
                                </span>
                                <small class="field-note">${escapeHTML(field.note)}</small>
                                ${current.enabled ? `
                                    <div class="override-field-row__input">
                                        ${control}
                                    </div>
                                ` : ''}
                            </label>
                        `;
    }).join('')}
                </div>
            </div>
        </details>
    `;
}

export function renderPacketOverridesModule({schema, state}) {
    const busy = state.savingStoredOverride || state.deletingStoredOverrideName;
    const isEditing = Boolean(state.selectedStoredOverrideName);

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Packet Overrides', 'Compact layer overrides for outbound traffic.')}

            <main class="single-panel-layout single-panel-layout--wide">
                ${state.storedOverridesError ? renderMessageBanner('Packet override notice', state.storedOverridesError) : ''}
                ${state.storedOverrideNotice ? renderMessageBanner('Packet override saved', state.storedOverrideNotice) : ''}

                <section class="override-layout">
                    <section class="panel section-panel section-panel--compact">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Library</span>
                                <h3>Stored overrides</h3>
                                <p>Reusable packet edits.</p>
                            </div>
                            <button class="ghost-button" type="button" data-new-stored-override ${busy ? 'disabled' : ''}>
                                New
                            </button>
                        </div>

                        ${renderStoredOverrideList(state)}
                    </section>

                    <section class="panel section-panel section-panel--compact form-panel">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Editor</span>
                                <h3>${isEditing ? escapeHTML(state.selectedStoredOverrideName) : 'New override'}</h3>
                                <p>${isEditing ? 'Update enabled layer fields.' : 'Open only the layers you need.'}</p>
                            </div>
                        </div>

                        <form id="stored-packet-override-form" class="form-stack form-stack--compact">
                            <label class="form-field">
                                <span>Name</span>
                                <input
                                    type="text"
                                    name="name"
                                    value="${escapeHTML(state.overrideEditor.name)}"
                                    autocomplete="off"
                                    spellcheck="false"
                                    data-override-name
                                    ${(busy || isEditing) ? 'disabled' : ''}
                                />
                                <small class="field-note">Stored filename and dropdown label.</small>
                            </label>

                            ${schema.map((section) => renderLayerSection(section, state.overrideEditor, busy)).join('')}

                            <div class="form-actions form-actions--compact">
                                <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                                    ${state.savingStoredOverride ? 'Saving...' : 'Save'}
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-override ${busy ? 'disabled' : ''}>
                                    Reset
                                </button>
                            </div>
                        </form>
                    </section>
                </section>
            </main>
        </div>
    `;
}
