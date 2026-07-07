import {basicEditor} from 'prism-code-editor/setups';
import 'prism-code-editor/prism/languages/python';
import {SCRIPT_EDITOR_THEME} from './scriptEditorOptions';

let editor = null;
let updatingFromState = false;

const editorCss = `
:host {
    display: block;
    width: 100%;
    height: 100%;
    min-height: 0;
}

.prism-code-editor {
    width: 100%;
    height: 100%;
    min-height: 0;
    margin: 0;
}
`;

function isReadOnly(state) {
    return Boolean(state.savingStoredScript || state.deletingStoredScriptName || state.deletingGenericScriptName);
}

function selectedThemeName(state) {
    return state.scriptEditorPreferences?.theme || SCRIPT_EDITOR_THEME;
}

function fontSizeFor(state) {
    return `${Number.parseInt(state.scriptEditorPreferences?.fontSize, 10) || 14}px`;
}

function normalizeText(text) {
    return text.replace(/\r\n?/g, '\n').replace(/\u00a0/g, ' ');
}

function installEditorStyles(host) {
    const shadow = host.shadowRoot;
    if (!shadow) {
        return;
    }

    let style = shadow.getElementById('kraken-editor-host-style');
    if (!style) {
        style = document.createElement('style');
        style.id = 'kraken-editor-host-style';
        shadow.append(style);
    }
    style.textContent = editorCss;
}

function applyEditorOptions(state) {
    editor.container.style.fontSize = fontSizeFor(state);
    editor.setOptions({
        readOnly: isReadOnly(state),
        theme: selectedThemeName(state),
    });
}

function setEditorValueFromState(state) {
    const nextValue = String(state.scriptEditor.source || '');
    if (editor.value === nextValue) {
        return;
    }

    const selectionStart = editor.textarea.selectionStart;
    const selectionEnd = editor.textarea.selectionEnd;
    const selectionDirection = editor.textarea.selectionDirection;
    const scrollTop = editor.container.scrollTop;
    const scrollLeft = editor.container.scrollLeft;

    updatingFromState = true;
    editor.setOptions({value: nextValue});
    updatingFromState = false;

    const max = editor.textarea.value.length;
    editor.textarea.setSelectionRange(
        Math.min(selectionStart, max),
        Math.min(selectionEnd, max),
        selectionDirection,
    );
    editor.container.scrollTop = scrollTop;
    editor.container.scrollLeft = scrollLeft;
}

function createScriptEditor(host, state) {
    editor = basicEditor(
        host,
        {
            language: 'python',
            lineNumbers: true,
            tabSize: 4,
            theme: selectedThemeName(state),
            value: String(state.scriptEditor.source || ''),
            onUpdate(value) {
                if (updatingFromState) {
                    return;
                }
                state.scriptEditor.source = normalizeText(value);
                if (state.activeScriptKind === 'generic') {
                    state.genericScriptsError = '';
                    state.genericScriptNotice = '';
                } else {
                    state.storedScriptsError = '';
                    state.storedScriptNotice = '';
                }
            },
        },
        () => installEditorStyles(host),
    );

    editor.host = host;
    editor.textarea.setAttribute('aria-label', 'Starlark source editor');
    installEditorStyles(host);
    applyEditorOptions(state);
}

function destroyEditor() {
    if (!editor) {
        return;
    }
    editor.remove();
    editor = null;
}

export function syncScriptCodeEditor(root, state) {
    const host = root.querySelector('[data-script-code-host]');
    if (!host) {
        destroyEditor();
        return;
    }

    if (!editor || editor.host !== host) {
        destroyEditor();
        createScriptEditor(host, state);
    }

    setEditorValueFromState(state);
    applyEditorOptions(state);
}
