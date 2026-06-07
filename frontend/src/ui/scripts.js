import {
    escapeHTML,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {
    SCRIPT_EDITOR_FONT_SIZE_OPTIONS,
    SCRIPT_EDITOR_THEME_OPTIONS,
} from '../scriptEditorOptions';
import {
    SCRIPT_SURFACE_APPLICATION,
    SCRIPT_SURFACE_TRANSPORT,
} from '../scriptModel';

const SCRIPT_SURFACE_ITEMS = [
    [SCRIPT_SURFACE_TRANSPORT, 'Transport'],
    [SCRIPT_SURFACE_APPLICATION, 'Application'],
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
        <nav class="script-surface-tabs" aria-label="Script surfaces">
            ${SCRIPT_SURFACE_ITEMS.map(([value, label]) => `
                <button
                    class="script-surface-tab ${selectedSurface === value ? 'is-active' : ''}"
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
        const label = surface === SCRIPT_SURFACE_TRANSPORT ? 'transport' : 'application';
        return `<div class="empty-state">No ${label} scripts.</div>`;
    }

    return `
        <div class="stored-script-list">
            ${visibleScripts.map((item) => {
        const isSelected = state.selectedStoredScriptKey === item.key;
        const isPendingDelete = state.pendingDeleteStoredScript === item.key;
        const busy = state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading;
        const status = item.available ? 'Ready' : 'Issue';
        const detail = item.available ? '' : item.compileError || 'Unavailable';

        return `
                    <article class="stored-script-row ${isSelected ? 'is-selected' : ''}">
                        <div class="stored-script-row__main">
                            <div class="stored-script-row__name">
                                <strong>${escapeHTML(item.name)}</strong>
                            </div>
                            <span class="stored-script-row__status ${item.available ? 'is-ready' : 'has-issue'}">${escapeHTML(status)}</span>
                            ${detail ? `<p>${escapeHTML(detail)}</p>` : ''}
                        </div>

                        ${isPendingDelete ? `
                            <div class="stored-script-row__actions stored-script-row__actions--confirm">
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
                            <div class="stored-script-row__actions">
                                <button
                                    class="ghost-button"
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
    const writing = state.savingStoredScript || state.deletingStoredScriptName;
    const listBusy = writing || state.storedScriptsLoading;
    const isEditing = Boolean(state.selectedStoredScriptKey);
    const preferences = state.scriptEditorPreferences;
    const activeSurface = state.selectedStoredScriptSurface || SCRIPT_SURFACE_TRANSPORT;
    const surfaceLabel = activeSurface === SCRIPT_SURFACE_TRANSPORT ? 'transport' : 'application';

    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Scripts')}

            <main class="single-panel-layout single-panel-layout--wide script-workspace">
                ${state.storedScriptsError ? renderMessageBanner('Scripts', state.storedScriptsError) : ''}
                ${state.storedScriptNotice ? renderMessageBanner('Saved', state.storedScriptNotice) : ''}

                <section class="script-layout">
                    <aside class="script-library">
                        <div class="script-section-heading">
                            <h3>Library</h3>
                            <div class="script-section-actions">
                                <button class="ghost-button" type="button" data-refresh-stored-scripts ${listBusy ? 'disabled' : ''}>
                                    Refresh
                                </button>
                                <button class="ghost-button" type="button" data-new-stored-script ${writing ? 'disabled' : ''}>
                                    New
                                </button>
                            </div>
                        </div>

                        ${renderSurfaceTabs(activeSurface)}
                        ${renderStoredScriptList(state, activeSurface)}
                    </aside>

                    <section class="script-editor-panel">
                        <div class="script-section-heading">
                            <h3>${isEditing ? escapeHTML(state.scriptEditor.name) : `New ${escapeHTML(surfaceLabel)} script`}</h3>
                        </div>

                        <form id="stored-script-form" class="stored-script-form">
                            <div class="script-editor-toolbar">
                                <label class="adopt-control script-editor-toolbar__name">
                                    <span>Name</span>
                                    <input
                                        type="text"
                                        name="name"
                                        value="${escapeHTML(state.scriptEditor.name)}"
                                        autocomplete="off"
                                        spellcheck="false"
                                        data-script-field="name"
                                        ${(writing || isEditing) ? 'disabled' : ''}
                                    />
                                </label>

                                <label class="adopt-control script-editor-toolbar__theme">
                                    <span>Theme</span>
                                    <select name="editorTheme" data-script-editor-preference="theme">
                                        ${renderPreferenceOptions(SCRIPT_EDITOR_THEME_OPTIONS, preferences.theme)}
                                    </select>
                                </label>

                                <label class="adopt-control script-editor-toolbar__size">
                                    <span>Size</span>
                                    <select name="editorFontSize" data-script-editor-preference="fontSize">
                                        ${renderPreferenceOptions(SCRIPT_EDITOR_FONT_SIZE_OPTIONS, preferences.fontSize)}
                                    </select>
                                </label>
                            </div>

                            <div class="script-source-field">
                                <div class="script-source-field__label">
                                    <span>Source</span>
                                    ${state.scriptEditor.updatedAt ? `<time>${escapeHTML(state.scriptEditor.updatedAt)}</time>` : ''}
                                </div>
                                <div class="script-editor-shell">
                                    <div
                                        class="script-editor script-editor-prism"
                                        data-script-code-host
                                        role="textbox"
                                        aria-label="Starlark source editor"
                                    ></div>
                                </div>
                            </div>

                            <div class="stored-script-actions">
                                <button class="adopt-submit" type="submit" ${writing ? 'disabled' : ''}>
                                    ${state.savingStoredScript ? 'Saving...' : 'Save'}
                                </button>
                                <button class="adopt-cancel" type="button" data-new-stored-script ${writing ? 'disabled' : ''}>
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
