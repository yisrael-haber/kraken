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
function renderPreferenceOptions(items) {
    return items.map((item) => `
        <wa-option value="${escapeHTML(item.value)}">
            ${escapeHTML(item.label)}
        </wa-option>
    `).join('');
}

function renderScriptPickerOptions(scripts) {
    return [
        '<wa-option value="">New script</wa-option>',
        ...scripts.map((script) => `
            <wa-option value="${escapeHTML(script.name)}">
                ${escapeHTML(script.available ? script.name : `${script.name} (Issue)`)}
            </wa-option>
        `),
    ].join('');
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
    return `
        <div class="module-frame module-frame--script">
            ${renderModuleTopbar(title)}

            <main class="single-panel-layout single-panel-layout--script">
                ${error ? renderMessageBanner('Scripts', error) : ''}
                ${notice ? renderMessageBanner('Saved', notice, 'success') : ''}
                ${isGeneric
                    ? renderGlobalScriptingWorkspace(state, {writing, loading, listBusy, isEditing, preferences})
                    : renderScriptEditorWorkspace(state, {writing, loading, listBusy, isEditing, preferences})}
            </main>
        </div>
    `;
}

function renderGlobalScriptingWorkspace(state, editorOptions) {
    const selectedTab = state.selectedGlobalScriptingTab === GLOBAL_SCRIPTING_TAB_RUN
        ? GLOBAL_SCRIPTING_TAB_RUN
        : GLOBAL_SCRIPTING_TAB_EDITOR;
    return `
        <wa-tab-group class="global-scripting-tabs" active="${selectedTab}" data-global-scripting-tabs>
            <wa-tab panel="${GLOBAL_SCRIPTING_TAB_EDITOR}" ${selectedTab === GLOBAL_SCRIPTING_TAB_EDITOR ? 'active' : ''}>Editor</wa-tab>
            <wa-tab panel="${GLOBAL_SCRIPTING_TAB_RUN}" ${selectedTab === GLOBAL_SCRIPTING_TAB_RUN ? 'active' : ''}>Run</wa-tab>
            <wa-tab-panel name="${GLOBAL_SCRIPTING_TAB_EDITOR}" ${selectedTab === GLOBAL_SCRIPTING_TAB_EDITOR ? 'active' : ''}>
                ${selectedTab === GLOBAL_SCRIPTING_TAB_EDITOR ? renderScriptEditorWorkspace(state, editorOptions) : ''}
            </wa-tab-panel>
            <wa-tab-panel name="${GLOBAL_SCRIPTING_TAB_RUN}" ${selectedTab === GLOBAL_SCRIPTING_TAB_RUN ? 'active' : ''}>
                ${selectedTab === GLOBAL_SCRIPTING_TAB_RUN ? renderGenericExecutionPanel(state) : ''}
            </wa-tab-panel>
        </wa-tab-group>
    `;
}

function renderScriptEditorWorkspace(state, {writing, loading, listBusy, isEditing, preferences}) {
    const isGeneric = state.activeScriptKind === SCRIPT_KIND_GENERIC;
    const scripts = isGeneric ? state.genericScripts : state.storedScripts;
    const selectedKey = isGeneric ? state.selectedGenericScriptKey : state.selectedStoredScriptKey;
    const pendingDelete = isGeneric ? state.pendingDeleteGenericScript : state.pendingDeleteStoredScript;
    const deletingName = isGeneric ? state.deletingGenericScriptName : state.deletingStoredScriptName;
    const selectedScript = scripts.find((script) => script.name === selectedKey) || null;
    return `
        <section class="script-editor-workspace">
            <form id="stored-script-form" class="stored-script-form">
                <div class="script-document-bar ${isEditing ? '' : 'script-document-bar--new'}">
                    <wa-select label="Script" value="${escapeHTML(selectedKey)}" appearance="filled" size="xs" data-stored-script-selection ${listBusy || pendingDelete ? 'disabled' : ''}>
                        ${renderScriptPickerOptions(scripts)}
                    </wa-select>
                    ${isEditing ? '' : `
                        <wa-input class="script-name-field" label="Name" type="text" name="name" value="${escapeHTML(state.scriptEditor.name)}" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-script-field="name" ${writing ? 'disabled' : ''}></wa-input>
                    `}
                    ${pendingDelete === selectedKey && selectedKey ? `
                        <div class="inline-confirmation">
                            <span class="inline-confirm">Delete ${escapeHTML(selectedKey)}?</span>
                            <wa-button variant="danger" appearance="plain" size="xs" type="button" data-confirm-delete-stored-script="${escapeHTML(selectedKey)}" ${deletingName === selectedKey ? 'loading' : ''} ${deletingName ? 'disabled' : ''}>Delete</wa-button>
                            <wa-button appearance="plain" size="xs" type="button" data-cancel-delete-stored-script ${deletingName ? 'disabled' : ''}>Cancel</wa-button>
                        </div>
                    ` : `
                        <div class="script-document-actions">
                            <wa-button appearance="plain" size="xs" type="button" data-refresh-stored-scripts ${loading ? 'loading' : ''} ${listBusy ? 'disabled' : ''}>Refresh</wa-button>
                            <wa-button appearance="plain" size="xs" type="button" data-stage-delete-stored-script="${escapeHTML(selectedKey)}" ${listBusy || !selectedKey ? 'disabled' : ''}>Delete</wa-button>
                            <wa-button variant="brand" appearance="outlined" size="xs" type="submit" ${state.savingStoredScript ? 'loading' : ''} ${writing ? 'disabled' : ''}>Save</wa-button>
                        </div>
                    `}
                </div>
                ${selectedScript && !selectedScript.available ? `<p class="field-note">${escapeHTML(selectedScript.compileError || 'This script has a compile issue.')}</p>` : ''}

                <div class="script-preferences" aria-label="Editor appearance">
                    <wa-select label="Theme" value="${escapeHTML(preferences.theme)}" appearance="filled" size="xs" data-script-editor-preference="theme">
                        ${renderPreferenceOptions(SCRIPT_EDITOR_THEME_OPTIONS)}
                    </wa-select>
                    <wa-select label="Size" value="${escapeHTML(preferences.fontSize)}" appearance="filled" size="xs" data-script-editor-preference="fontSize">
                        ${renderPreferenceOptions(SCRIPT_EDITOR_FONT_SIZE_OPTIONS)}
                    </wa-select>
                </div>

                <div class="script-source-field">
                    <span class="script-source-field__label">Source</span>
                    <div class="script-editor-shell">
                        <div
                            class="script-editor"
                            data-script-code-host
                            role="textbox"
                            aria-label="Starlark source editor"
                        ></div>
                    </div>
                </div>

            </form>
        </section>
    `;
}

function renderGenericExecutionPanel(state) {
    const availableScripts = state.genericScripts.filter((item) => item.available);
    const selected = state.selectedGenericRunScriptName || availableScripts[0]?.name || '';
    const stdout = state.genericScriptRunResult?.stdout || '';
    const stderr = state.genericScriptRunResult?.stderr || '';
    const failure = stderr || state.genericScriptRunError;
    const output = stdout && failure
        ? `${stdout}${stdout.endsWith('\n') ? '' : '\n'}${failure}`
        : stdout || failure;
    const busy = state.runningGenericScript || state.genericScriptsLoading;

    return `
        <section class="script-run-workspace">
            <div class="script-run-controls">
                <wa-select label="Script" value="${escapeHTML(selected)}" appearance="filled" size="xs" data-generic-run-script-name ${busy ? 'disabled' : ''}>
                    ${availableScripts.length ? availableScripts.map((script) => `
                        <wa-option value="${escapeHTML(script.name)}">${escapeHTML(script.name)}</wa-option>
                    `).join('') : '<wa-option value="">No runnable scripts</wa-option>'}
                </wa-select>
                <div class="script-run-actions">
                    <wa-button variant="brand" appearance="outlined" size="xs" type="button" data-run-generic-script ${state.runningGenericScript ? 'loading' : ''} ${busy || !selected ? 'disabled' : ''}>Run</wa-button>
                    <wa-button variant="danger" appearance="plain" size="xs" type="button" data-stop-generic-script ${state.runningGenericScript ? '' : 'disabled'}>Stop</wa-button>
                </div>
            </div>
            <div class="script-output">
                <div class="script-output__header">
                    <span>Output</span>
                    <wa-badge appearance="outlined" variant="neutral" pill>${state.runningGenericScript ? 'Running' : 'Idle'}</wa-badge>
                </div>
                <pre aria-live="polite">${escapeHTML(output)}</pre>
            </div>
        </section>
    `;
}
