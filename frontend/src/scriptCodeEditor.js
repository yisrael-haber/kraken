import {createEditor} from 'prism-code-editor';
import 'prism-code-editor/prism/languages/python';
import layoutCss from '../node_modules/prism-code-editor/dist/layout.css?inline';
import githubDarkDimmedThemeCss from '../node_modules/prism-code-editor/dist/themes/github-dark-dimmed.css?inline';
import githubDarkThemeCss from '../node_modules/prism-code-editor/dist/themes/github-dark.css?inline';
import prismOkaidiaThemeCss from '../node_modules/prism-code-editor/dist/themes/prism-okaidia.css?inline';
import solarizedDarkAtomThemeCss from './themes/prism-solarized-dark-atom.css?inline';

let editor = null;
let hostElement = null;
let suppressChange = false;
let styleElement = null;
let appliedTheme = '';
let appliedFontSize = 0;
let appliedReadOnly = false;

const themeStyles = {
    'github-dark-dimmed': githubDarkDimmedThemeCss,
    'github-dark': githubDarkThemeCss,
    'prism-okaidia': prismOkaidiaThemeCss,
    'solarized-dark-atom': solarizedDarkAtomThemeCss,
};
// Prism doesn't ship a Starlark grammar, so Python is the closest built-in highlighter here.
const scriptEditorLanguage = 'python';

function styleTextForTheme(name) {
    return `${layoutCss}\n${themeStyles[name] || prismOkaidiaThemeCss}`;
}

function isReadOnly(state) {
    return Boolean(state.savingStoredScript || state.deletingStoredScriptName || state.storedScriptsLoading);
}

function destroyEditor() {
    if (editor) {
        editor.remove();
    }
    hostElement?.shadowRoot?.replaceChildren();
    editor = null;
    hostElement = null;
    styleElement = null;
    suppressChange = false;
    appliedTheme = '';
    appliedFontSize = 0;
    appliedReadOnly = false;
}

function applyEditorPresentation(state) {
    if (!editor || !hostElement) {
        return;
    }

    const preferences = state.scriptEditorPreferences || {};
    const theme = String(preferences.theme || 'prism-okaidia');
    const fontSize = Number.parseInt(preferences.fontSize, 10) || 14;
    const readOnly = isReadOnly(state);

    if (styleElement && appliedTheme !== theme) {
        styleElement.textContent = styleTextForTheme(theme);
        appliedTheme = theme;
    }

    editor.container.style.height = '100%';
    editor.container.style.lineHeight = '1.55';
    editor.wrapper.style.margin = '0.35rem 0';
    editor.wrapper.style.minHeight = '100%';
    if (appliedFontSize !== fontSize) {
        editor.container.style.fontSize = `${fontSize}px`;
        appliedFontSize = fontSize;
    }
    if (appliedReadOnly !== readOnly) {
        editor.setOptions({readOnly});
        appliedReadOnly = readOnly;
    }

    hostElement.classList.toggle('is-readonly', readOnly);
}

function createScriptEditor(host, state) {
    const shadow = host.shadowRoot || host.attachShadow({mode: 'open'});
    styleElement = document.createElement('style');
    styleElement.textContent = styleTextForTheme(state.scriptEditorPreferences?.theme || 'prism-okaidia');
    shadow.replaceChildren(styleElement);

    editor = createEditor(shadow, {
        language: scriptEditorLanguage,
        value: String(state.scriptEditor.source || ''),
        tabSize: 4,
        insertSpaces: true,
        wordWrap: false,
        lineNumbers: true,
        readOnly: isReadOnly(state),
        onUpdate(value) {
            if (suppressChange) {
                return;
            }
            state.scriptEditor.source = value;
            state.storedScriptsError = '';
            state.storedScriptNotice = '';
        },
    });
    hostElement = host;
    appliedTheme = '';
    appliedFontSize = 0;
    appliedReadOnly = !isReadOnly(state);
    applyEditorPresentation(state);
}

function syncEditorValue(state) {
    if (!editor) {
        return;
    }

    const nextValue = String(state.scriptEditor.source || '');
    if (editor.value === nextValue) {
        return;
    }

    suppressChange = true;
    editor.setOptions({value: nextValue});
    suppressChange = false;
}

export function syncScriptCodeEditor(root, state) {
    const host = root.querySelector('[data-script-code-host]');
    if (!host) {
        destroyEditor();
        return;
    }

    if (host !== hostElement) {
        destroyEditor();
        createScriptEditor(host, state);
    }

    syncEditorValue(state);
    applyEditorPresentation(state);
}
