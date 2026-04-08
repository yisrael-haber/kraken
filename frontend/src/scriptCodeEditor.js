import {createEditor} from 'prism-code-editor';
import 'prism-code-editor/prism/languages/javascript';
import layoutCss from '../node_modules/prism-code-editor/dist/layout.css?inline';
import githubDarkDimmedThemeCss from '../node_modules/prism-code-editor/dist/themes/github-dark-dimmed.css?inline';
import githubDarkThemeCss from '../node_modules/prism-code-editor/dist/themes/github-dark.css?inline';
import prismOkaidiaThemeCss from '../node_modules/prism-code-editor/dist/themes/prism-okaidia.css?inline';
import solarizedDarkAtomThemeCss from './themes/prism-solarized-dark-atom.css?inline';

let editor = null;
let hostElement = null;
let suppressChange = false;
let styleElement = null;

const themeStyles = {
    'github-dark-dimmed': githubDarkDimmedThemeCss,
    'github-dark': githubDarkThemeCss,
    'prism-okaidia': prismOkaidiaThemeCss,
    'solarized-dark-atom': solarizedDarkAtomThemeCss,
};

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
}

function applyEditorPresentation(state) {
    if (!editor || !hostElement) {
        return;
    }

    const preferences = state.scriptEditorPreferences || {};
    const theme = String(preferences.theme || 'prism-okaidia');
    const fontSize = Number.parseInt(preferences.fontSize, 10) || 14;
    const readOnly = isReadOnly(state);

    if (styleElement) {
        styleElement.textContent = styleTextForTheme(theme);
    }

    editor.container.style.fontSize = `${fontSize}px`;
    editor.container.style.height = '100%';
    editor.container.style.lineHeight = '1.55';
    editor.wrapper.style.margin = '0.35rem 0';
    editor.wrapper.style.minHeight = '100%';
    editor.setOptions({
        language: 'javascript',
        tabSize: 4,
        insertSpaces: true,
        wordWrap: false,
        lineNumbers: true,
        readOnly,
    });

    hostElement.classList.toggle('is-readonly', readOnly);
}

function createScriptEditor(host, state) {
    const shadow = host.shadowRoot || host.attachShadow({mode: 'open'});
    styleElement = document.createElement('style');
    styleElement.textContent = styleTextForTheme(state.scriptEditorPreferences?.theme || 'prism-okaidia');
    shadow.replaceChildren(styleElement);

    editor = createEditor(shadow, {
        language: 'javascript',
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
