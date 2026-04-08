import {
    escapeHTML,
    pill,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {
    SCRIPT_EDITOR_FONT_SIZE_OPTIONS,
    SCRIPT_EDITOR_FONT_SIZE_MAX,
    SCRIPT_EDITOR_FONT_SIZE_MIN,
    SCRIPT_EDITOR_THEME_OPTIONS,
} from '../scriptEditorOptions';

function renderPreferenceOptions(items, selectedValue) {
    return items.map((item) => `
        <option value="${escapeHTML(item.value)}" ${item.value === selectedValue ? 'selected' : ''}>
            ${escapeHTML(item.label)}
        </option>
    `).join('');
}

function renderStoredScriptList(state) {
    if (state.storedScriptsLoading && !state.storedScripts.length) {
        return '<div class="empty-state">Loading stored scripts...</div>';
    }

    if (!state.storedScripts.length) {
        return '<div class="empty-state">No JS scripts yet.</div>';
    }

    return `
        <div class="config-card-list config-card-list--compact">
            ${state.storedScripts.map((item) => {
        const isSelected = state.selectedStoredScriptName === item.name;
        const isPendingDelete = state.pendingDeleteStoredScript === item.name;
        const busy = state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading;

        return `
                    <article class="panel compact-list-card override-card ${isSelected ? 'is-selected' : ''}">
                        <div class="compact-list-card__row">
                            <div>
                                <strong>${escapeHTML(item.name)}</strong>
                                <p>${escapeHTML(item.available ? 'Compiled and ready.' : item.compileError || 'Unavailable.')}</p>
                            </div>
                            ${item.available ? pill('Ready', 'success') : pill('Issue', 'warn')}
                        </div>

                        ${isPendingDelete ? `
                            <div class="section-actions section-actions--confirm">
                                <span class="inline-confirm">Delete this script?</span>
                                <button
                                    class="danger-button"
                                    type="button"
                                    data-confirm-delete-stored-script="${escapeHTML(item.name)}"
                                    ${state.deletingStoredScriptName ? 'disabled' : ''}
                                >
                                    ${state.deletingStoredScriptName === item.name ? 'Deleting...' : 'Delete'}
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-cancel-delete-stored-script
                                    ${state.deletingStoredScriptName ? 'disabled' : ''}
                                >
                                    Cancel
                                </button>
                            </div>
                        ` : `
                            <div class="section-actions">
                                <button
                                    class="primary-button"
                                    type="button"
                                    data-edit-stored-script="${escapeHTML(item.name)}"
                                    ${busy ? 'disabled' : ''}
                                >
                                    Edit
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-stage-delete-stored-script="${escapeHTML(item.name)}"
                                    ${busy ? 'disabled' : ''}
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

export function renderScriptsModule({state}) {
    const busy = state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading;
    const isEditing = Boolean(state.selectedStoredScriptName);
    const preferences = state.scriptEditorPreferences;

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('JS Scripts', 'Filesystem-backed packet editing scripts.')}

            <main class="single-panel-layout single-panel-layout--wide script-workspace">
                ${state.storedScriptsError ? renderMessageBanner('Script notice', state.storedScriptsError) : ''}
                ${state.storedScriptNotice ? renderMessageBanner('Script update', state.storedScriptNotice) : ''}

                <section class="override-layout script-layout">
                    <section class="panel section-panel section-panel--compact">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Inventory</span>
                                <h3>Stored scripts</h3>
                                <p>Compiled from Kraken config scripts.</p>
                            </div>
                            <div class="section-actions">
                                <button class="ghost-button" type="button" data-refresh-stored-scripts ${busy ? 'disabled' : ''}>
                                    Refresh
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-script ${busy ? 'disabled' : ''}>
                                    New
                                </button>
                            </div>
                        </div>

                        ${renderStoredScriptList(state)}
                    </section>

                    <section class="panel section-panel section-panel--compact form-panel script-editor-panel">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Editor</span>
                                <h3>${isEditing ? escapeHTML(state.selectedStoredScriptName) : 'New script'}</h3>
                                <p>${isEditing ? 'Edit the source and save to recompile.' : 'Create a packet editing script with a main(packet, ctx) entrypoint.'}</p>
                            </div>
                        </div>

                        <form id="stored-script-form" class="form-stack form-stack--compact">
                            <div class="script-editor-toolbar">
                                <label class="form-field script-editor-toolbar__name">
                                    <span>Name</span>
                                    <input
                                        type="text"
                                        name="name"
                                        value="${escapeHTML(state.scriptEditor.name)}"
                                        autocomplete="off"
                                        spellcheck="false"
                                        data-script-field="name"
                                        ${(busy || isEditing) ? 'disabled' : ''}
                                    />
                                    <small class="field-note">Filename and dropdown label.</small>
                                </label>

                                <div class="script-editor-toolbar__pair">
                                    <label class="form-field">
                                        <span>Theme</span>
                                        <select name="editorTheme" data-script-editor-preference="theme">
                                            ${renderPreferenceOptions(SCRIPT_EDITOR_THEME_OPTIONS, preferences.theme)}
                                        </select>
                                        <small class="field-note">Switch the dark editor palette.</small>
                                    </label>

                                    <label class="form-field">
                                        <span>Font Size</span>
                                        <select name="editorFontSize" data-script-editor-preference="fontSize">
                                            ${renderPreferenceOptions(SCRIPT_EDITOR_FONT_SIZE_OPTIONS, preferences.fontSize)}
                                        </select>
                                        <small class="field-note">Line numbers stay on. Range: ${SCRIPT_EDITOR_FONT_SIZE_MIN}-${SCRIPT_EDITOR_FONT_SIZE_MAX} px.</small>
                                    </label>
                                </div>
                            </div>

                            <label class="form-field">
                                <span>Source</span>
                                <div class="script-editor-shell">
                                    <div
                                        class="script-editor script-editor-prism"
                                        data-script-code-host
                                        role="textbox"
                                        aria-label="JavaScript source editor"
                                    ></div>
                                </div>
                                <small class="field-note">Entrypoint: <code>main(packet, ctx)</code>.</small>
                            </label>

                            ${state.scriptEditor.updatedAt ? `
                                <p class="field-note">Last compiled snapshot: ${escapeHTML(state.scriptEditor.updatedAt)}</p>
                            ` : ''}

                            <div class="form-actions form-actions--compact">
                                <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                                    ${state.savingStoredScript ? 'Saving...' : 'Save'}
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-script ${busy ? 'disabled' : ''}>
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
