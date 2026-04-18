import {
    escapeHTML,
    pill,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {
    SCRIPT_EDITOR_FONT_SIZE_OPTIONS,
    SCRIPT_EDITOR_THEME_OPTIONS,
} from '../scriptEditorOptions';
import {
    SCRIPT_SURFACE_HTTP_SERVICE,
    SCRIPT_SURFACE_PACKET,
} from '../scriptModel';

const SCRIPT_SURFACE_ITEMS = [
    [SCRIPT_SURFACE_PACKET, 'Transport'],
    [SCRIPT_SURFACE_HTTP_SERVICE, 'Application'],
];

const SCRIPT_PROTOCOL_ITEMS = [
    [SCRIPT_SURFACE_HTTP_SERVICE, 'HTTP'],
];

function renderPreferenceOptions(items, selectedValue) {
    return items.map((item) => `
        <option value="${escapeHTML(item.value)}" ${item.value === selectedValue ? 'selected' : ''}>
            ${escapeHTML(item.label)}
        </option>
    `).join('');
}

function renderSurfaceTabs(selectedSurface) {
    return `
        <nav class="tab-strip" aria-label="Script surfaces">
            ${SCRIPT_SURFACE_ITEMS.map(([value, label]) => `
                <button
                    class="tab-button ${selectedSurface === value ? 'is-active' : ''}"
                    type="button"
                    data-script-surface="${escapeHTML(value)}"
                    aria-pressed="${selectedSurface === value ? 'true' : 'false'}"
                >
                    ${escapeHTML(label)}
                </button>
            `).join('')}
        </nav>
    `;
}

function renderApplicationProtocolTabs(selectedSurface) {
    if (selectedSurface !== SCRIPT_SURFACE_HTTP_SERVICE) {
        return '';
    }

    return `
        <nav class="tab-strip tab-strip--subtle" aria-label="Application protocols">
            ${SCRIPT_PROTOCOL_ITEMS.map(([value, label]) => `
                <button
                    class="tab-button tab-button--subtle ${selectedSurface === value ? 'is-active' : ''}"
                    type="button"
                    data-script-surface="${escapeHTML(value)}"
                    aria-pressed="${selectedSurface === value ? 'true' : 'false'}"
                >
                    ${escapeHTML(label)}
                </button>
            `).join('')}
        </nav>
    `;
}

function renderStoredScriptList(state, surface) {
    const visibleScripts = state.storedScripts.filter((item) => item.surface === surface);

    if (state.storedScriptsLoading && !state.storedScripts.length) {
        return '<div class="empty-state">Loading scripts.</div>';
    }

    if (!visibleScripts.length) {
        return `<div class="empty-state">No ${surface === SCRIPT_SURFACE_PACKET ? 'transport' : 'HTTP'} scripts.</div>`;
    }

    return `
        <div class="config-card-list config-card-list--compact">
            ${visibleScripts.map((item) => {
        const isSelected = state.selectedStoredScriptKey === item.key;
        const isPendingDelete = state.pendingDeleteStoredScript === item.key;
        const busy = state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading;

        return `
                    <article class="panel compact-list-card override-card ${isSelected ? 'is-selected' : ''}">
                        <div class="compact-list-card__row">
                            <div>
                                <strong>${escapeHTML(item.name)}</strong>
                                <p>${escapeHTML(item.available ? 'Compiled.' : item.compileError || 'Unavailable.')}</p>
                            </div>
                            ${item.available ? pill('Ready', 'success') : pill('Issue', 'warn')}
                        </div>

                        ${isPendingDelete ? `
                            <div class="section-actions section-actions--confirm">
                                <span class="inline-confirm">Delete this script?</span>
                                <button
                                    class="danger-button"
                                    type="button"
                                    data-confirm-delete-stored-script="${escapeHTML(item.key)}"
                                    ${state.deletingStoredScriptName ? 'disabled' : ''}
                                >
                                    ${state.deletingStoredScriptName === item.key ? 'Deleting...' : 'Delete'}
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
                                    data-edit-stored-script="${escapeHTML(item.key)}"
                                    ${busy ? 'disabled' : ''}
                                >
                                    Edit
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-stage-delete-stored-script="${escapeHTML(item.key)}"
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
    const isEditing = Boolean(state.selectedStoredScriptKey);
    const preferences = state.scriptEditorPreferences;
    const activeSurface = state.selectedStoredScriptSurface || SCRIPT_SURFACE_PACKET;
    const surfaceLabel = activeSurface === SCRIPT_SURFACE_HTTP_SERVICE ? 'HTTP' : 'transport';

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('')}

            <main class="single-panel-layout single-panel-layout--wide script-workspace">
                ${state.storedScriptsError ? renderMessageBanner('Scripts', state.storedScriptsError) : ''}
                ${state.storedScriptNotice ? renderMessageBanner('Saved', state.storedScriptNotice) : ''}

                ${renderSurfaceTabs(activeSurface)}
                ${renderApplicationProtocolTabs(activeSurface)}

                <section class="override-layout script-layout">
                    <section class="panel section-panel section-panel--compact">
                        <div class="section-heading section-heading--tight">
                            <h3>Library</h3>
                            <div class="section-actions">
                                <button class="ghost-button" type="button" data-refresh-stored-scripts ${busy ? 'disabled' : ''}>
                                    Refresh
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-script ${busy ? 'disabled' : ''}>
                                    New
                                </button>
                            </div>
                        </div>

                        ${renderStoredScriptList(state, activeSurface)}
                    </section>

                    <section class="panel section-panel section-panel--compact form-panel script-editor-panel">
                        <div class="section-heading section-heading--tight">
                            <h3>${isEditing ? escapeHTML(state.scriptEditor.name) : `New ${escapeHTML(surfaceLabel)} script`}</h3>
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
                                </label>

                                <div class="script-editor-toolbar__pair">
                                    <label class="form-field">
                                        <span>Theme</span>
                                        <select name="editorTheme" data-script-editor-preference="theme">
                                            ${renderPreferenceOptions(SCRIPT_EDITOR_THEME_OPTIONS, preferences.theme)}
                                        </select>
                                    </label>

                                    <label class="form-field">
                                        <span>Font Size</span>
                                        <select name="editorFontSize" data-script-editor-preference="fontSize">
                                            ${renderPreferenceOptions(SCRIPT_EDITOR_FONT_SIZE_OPTIONS, preferences.fontSize)}
                                        </select>
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
                                        aria-label="Starlark source editor"
                                    ></div>
                                </div>
                                <small class="field-note">Docs and examples live in the template comments.</small>
                            </label>

                            ${state.scriptEditor.updatedAt ? `
                                <p class="field-note">Last compile: ${escapeHTML(state.scriptEditor.updatedAt)}</p>
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
