import {
    escapeHTML,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {
    SCRIPT_EDITOR_FONT_SIZE_OPTIONS,
    SCRIPT_EDITOR_THEME_OPTIONS,
} from '../scriptEditorOptions';
import {SCRIPT_KIND_GENERIC} from '../scriptModel';
import {GLOBAL_SCRIPTING_TAB_EDITOR, GLOBAL_SCRIPTING_TAB_RUN} from '../app/state';
function renderPreferenceOptions(items, selectedValue) {
    return items.map((item) => `
        <option value="${escapeHTML(item.value)}" ${item.value === selectedValue ? 'selected' : ''}>
            ${escapeHTML(item.label)}
        </option>
    `).join('');
}

function renderStoredScriptList(state) {
    const isGeneric = state.activeScriptKind === SCRIPT_KIND_GENERIC;
    const scripts = isGeneric ? state.genericScripts : state.storedScripts;
    const loading = isGeneric ? state.genericScriptsLoading : state.storedScriptsLoading;
    const selectedKey = isGeneric ? state.selectedGenericScriptKey : state.selectedStoredScriptKey;
    const pendingDelete = isGeneric ? state.pendingDeleteGenericScript : state.pendingDeleteStoredScript;
    const deletingName = isGeneric ? state.deletingGenericScriptName : state.deletingStoredScriptName;

    if (loading && !scripts.length) {
        return '<div class="empty-state">Loading scripts.</div>';
    }

    if (!scripts.length) {
        return '<div class="empty-state">No scripts.</div>';
    }

    return `
        <div class="stored-script-list">
            ${scripts.map((item) => {
        const isSelected = selectedKey === item.name;
        const isPendingDelete = pendingDelete === item.name;
        const busy = state.savingStoredScript || deletingName || loading;
        const detail = item.available ? '' : item.compileError || 'Unavailable';

        return `
                    <article class="stored-script-row ${isSelected ? 'is-selected' : ''}">
                        <div class="stored-script-row__main">
                            <div class="stored-script-row__name">
                                <strong>${escapeHTML(item.name)}</strong>
                            </div>
                            ${item.available ? '' : '<span class="stored-script-row__status">Issue</span>'}
                            ${detail ? `<p>${escapeHTML(detail)}</p>` : ''}
                        </div>

                        ${isPendingDelete ? `
                            <div class="stored-script-row__actions stored-script-row__actions--confirm">
                                <span class="inline-confirm">Delete this script?</span>
                                <button
                                    class="danger-button"
                                    type="button"
                                    data-confirm-delete-stored-script="${escapeHTML(item.name)}"
                                    ${deletingName ? 'disabled' : ''}
                                >
                                    ${deletingName === item.name ? 'Deleting...' : 'Delete'}
                                </button>
                                <button
                                    class="ghost-button"
                                    type="button"
                                    data-cancel-delete-stored-script
                                    ${deletingName ? 'disabled' : ''}
                                >
                                    Cancel
                                </button>
                            </div>
                        ` : `
                            <div class="stored-script-row__actions">
                                <button
                                    class="ghost-button script-icon-button"
                                    type="button"
                                    data-edit-stored-script="${escapeHTML(item.name)}"
                                    ${busy ? 'disabled' : ''}
                                    aria-label="Edit ${escapeHTML(item.name)}"
                                    title="Edit script"
                                >
                                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 20 4.2-1 10.6-10.6-3.2-3.2L5 15.8 4 20Zm9.8-13 3.2 3.2" /></svg>
                                </button>
                                <button
                                    class="ghost-button script-icon-button script-delete-button"
                                    type="button"
                                    data-stage-delete-stored-script="${escapeHTML(item.name)}"
                                    ${busy ? 'disabled' : ''}
                                    aria-label="Delete ${escapeHTML(item.name)}"
                                    title="Delete script"
                                >
                                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3m3 0-1 13H7L6 7m4 4v5m4-5v5" /></svg>
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
    const isGeneric = state.activeScriptKind === SCRIPT_KIND_GENERIC;
    const deletingName = isGeneric ? state.deletingGenericScriptName : state.deletingStoredScriptName;
    const loading = isGeneric ? state.genericScriptsLoading : state.storedScriptsLoading;
    const error = isGeneric ? state.genericScriptsError : state.storedScriptsError;
    const notice = isGeneric ? state.genericScriptNotice : state.storedScriptNotice;
    const selectedKey = isGeneric ? state.selectedGenericScriptKey : state.selectedStoredScriptKey;
    const writing = state.savingStoredScript || deletingName;
    const listBusy = writing || loading;
    const isEditing = Boolean(selectedKey);
    const preferences = state.scriptEditorPreferences;
    const title = isGeneric ? 'Global scripting' : 'Transport scripts';
    const runTab = isGeneric && state.selectedGlobalScriptingTab === GLOBAL_SCRIPTING_TAB_RUN;
    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar(title)}

            <main class="single-panel-layout single-panel-layout--wide script-workspace">
                ${error ? renderMessageBanner('Scripts', error) : ''}
                ${notice ? renderMessageBanner('Saved', notice) : ''}
                ${isGeneric ? renderGlobalScriptingTabs(state) : ''}
                ${runTab
                    ? renderGenericExecutionPanel(state)
                    : renderScriptEditorWorkspace(state, {writing, listBusy, isEditing, preferences})}
            </main>
        </div>
    `;
}

function renderGlobalScriptingTabs(state) {
    return `
        <nav class="adopt-tabs script-subtabs" aria-label="Global scripting sections">
            <button class="tab-button ${state.selectedGlobalScriptingTab === GLOBAL_SCRIPTING_TAB_EDITOR ? 'is-active' : ''}" type="button" data-global-scripting-tab="${GLOBAL_SCRIPTING_TAB_EDITOR}">
                Editor
            </button>
            <button class="tab-button ${state.selectedGlobalScriptingTab === GLOBAL_SCRIPTING_TAB_RUN ? 'is-active' : ''}" type="button" data-global-scripting-tab="${GLOBAL_SCRIPTING_TAB_RUN}">
                Run
            </button>
        </nav>
    `;
}

function renderScriptEditorWorkspace(state, {writing, listBusy, isEditing, preferences}) {
    return `
        <section class="script-layout">
            <aside class="script-library">
                <div class="script-section-actions">
                    <button class="ghost-button script-icon-button" type="button" data-refresh-stored-scripts ${listBusy ? 'disabled' : ''} aria-label="Refresh scripts" title="Refresh">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6" /></svg>
                    </button>
                    <button class="ghost-button script-icon-button" type="button" data-new-stored-script ${writing ? 'disabled' : ''} aria-label="New script" title="New script">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
                    </button>
                </div>

                ${renderStoredScriptList(state)}
            </aside>

            <section class="script-editor-panel">
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

                        <div class="stored-script-actions">
                            <button class="adopt-submit" type="submit" ${writing ? 'disabled' : ''}>
                                ${state.savingStoredScript ? 'Saving...' : 'Save'}
                            </button>
                            <button class="adopt-cancel" type="button" data-new-stored-script ${writing ? 'disabled' : ''}>
                                Reset
                            </button>
                        </div>
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

                </form>
            </section>
        </section>
    `;
}

function renderGenericExecutionPanel(state) {
    const availableScripts = state.genericScripts.filter((item) => item.available);
    const selected = state.selectedGenericRunScriptName || availableScripts[0]?.name || '';
    const stdout = state.genericScriptRunResult?.stdout || '';
    const stderr = state.genericScriptRunResult?.stderr || '';
    const busy = state.runningGenericScript || state.genericScriptsLoading;

    return `
        <section class="script-run-panel panel">
            <div class="script-run-panel__controls">
                <label class="adopt-control">
                    <span>Script</span>
                    <select data-generic-run-script-name ${busy ? 'disabled' : ''}>
                        ${availableScripts.length ? availableScripts.map((script) => `
                            <option value="${escapeHTML(script.name)}" ${script.name === selected ? 'selected' : ''}>
                                ${escapeHTML(script.name)}
                            </option>
                        `).join('') : '<option value="">No generic scripts</option>'}
                    </select>
                </label>
                <div class="script-run-panel__buttons">
                    <button class="adopt-submit script-run-button" type="button" data-run-generic-script ${busy || !selected ? 'disabled' : ''} aria-label="Run script" title="Run">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7-11-7Z" /></svg>
                    </button>
                    <button class="danger-button script-run-button" type="button" data-stop-generic-script ${state.runningGenericScript ? '' : 'disabled'} aria-label="Stop script" title="Stop">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7h10v10H7z" /></svg>
                    </button>
                </div>
            </div>
            <div class="script-run-panel__output">
                <div>
                    <span>stdout</span>
                    <pre>${escapeHTML(stdout)}</pre>
                </div>
                <div>
                    <span>stderr</span>
                    <pre>${escapeHTML(stderr || state.genericScriptRunError || '')}</pre>
                </div>
            </div>
        </section>
    `;
}
