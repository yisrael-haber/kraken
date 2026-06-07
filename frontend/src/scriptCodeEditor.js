import {highlightText} from 'prism-code-editor/prism';
import 'prism-code-editor/prism/languages/python';
import githubDarkDimmedThemeCss from '../node_modules/prism-code-editor/dist/themes/github-dark-dimmed.css?inline';
import githubDarkThemeCss from '../node_modules/prism-code-editor/dist/themes/github-dark.css?inline';
import prismOkaidiaThemeCss from '../node_modules/prism-code-editor/dist/themes/prism-okaidia.css?inline';
import solarizedDarkAtomThemeCss from './themes/prism-solarized-dark-atom.css?inline';

let editor = null;

const themeStyles = {
    'github-dark-dimmed': githubDarkDimmedThemeCss,
    'github-dark': githubDarkThemeCss,
    'prism-okaidia': prismOkaidiaThemeCss,
    'solarized-dark-atom': solarizedDarkAtomThemeCss,
};

const themeVars = {
    'prism-okaidia': {
        background: '#272822',
        foreground: '#f8f8f2',
        gutter: '#8f908a',
        gutterBackground: '#24251f',
        border: '#42433d',
        selection: '#49483e',
        caret: '#f8f8f0',
    },
    'github-dark': {
        background: '#0d1117',
        foreground: '#e6edf3',
        gutter: '#6e7681',
        gutterBackground: '#0b1016',
        border: '#30363d',
        selection: '#264f78',
        caret: '#e6edf3',
    },
    'github-dark-dimmed': {
        background: '#22272e',
        foreground: '#adbac7',
        gutter: '#768390',
        gutterBackground: '#1d2229',
        border: '#444c56',
        selection: '#2d4f67',
        caret: '#adbac7',
    },
    'solarized-dark-atom': {
        background: '#002b36',
        foreground: '#93a1a1',
        gutter: '#586e75',
        gutterBackground: '#002630',
        border: '#19414a',
        selection: '#0f4a57',
        caret: '#839496',
    },
};

const editorCss = `
:host {
    display: block;
    width: 100%;
    height: 100%;
    min-height: 0;
}

.script-code-editor {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    width: 100%;
    height: 100%;
    min-height: 0;
    background: var(--editor-bg);
    color: var(--editor-fg);
    color-scheme: dark;
    font-family: "SFMono-Regular", "Consolas", monospace;
    font-size: var(--editor-font-size);
    font-variant-ligatures: none;
    line-height: 1.52;
    overflow: hidden;
}

.script-code-editor__gutter {
    min-width: 2.9rem;
    margin: 0;
    padding: 0.68rem 0.56rem 0.68rem 0;
    border-right: 1px solid var(--editor-border);
    background: var(--editor-gutter-bg);
    box-sizing: border-box;
    color: var(--editor-gutter);
    font-size: 0.92em;
    overflow: hidden;
    text-align: right;
    user-select: none;
    white-space: pre;
}

.script-code-editor__scroll {
    min-width: 0;
    min-height: 0;
    overflow: auto;
    overscroll-behavior: contain;
    scrollbar-gutter: stable;
}

.script-code-editor__input {
    min-width: max-content;
    min-height: 100%;
    padding: 0.68rem 0.86rem;
    box-sizing: border-box;
    caret-color: var(--editor-caret);
    color: inherit;
    outline: none;
    tab-size: 4;
    white-space: pre;
}

.script-code-editor__input::selection,
.script-code-editor__input *::selection {
    background: var(--editor-selection);
    color: var(--editor-fg);
}

.script-code-editor__input.is-readonly {
    opacity: 0.72;
    pointer-events: none;
}

@media (hover: hover) {
    .script-code-editor__scroll::-webkit-scrollbar {
        width: 0.62rem;
        height: 0.62rem;
    }

    .script-code-editor__scroll::-webkit-scrollbar-track,
    .script-code-editor__scroll::-webkit-scrollbar-corner {
        background: transparent;
    }

    .script-code-editor__scroll::-webkit-scrollbar-thumb {
        border: 2px solid transparent;
        border-radius: 999px;
        background-clip: content-box;
        background: color-mix(in srgb, var(--editor-gutter) 42%, transparent);
    }

    .script-code-editor__scroll::-webkit-scrollbar-thumb:hover {
        background: color-mix(in srgb, var(--editor-gutter) 62%, transparent);
    }
}
`;

function isReadOnly(state) {
    return Boolean(state.savingStoredScript || state.deletingStoredScriptName);
}

function themeNameFor(state) {
    return state.scriptEditorPreferences?.theme || 'prism-okaidia';
}

function themeFor(state) {
    return themeVars[themeNameFor(state)] || themeVars['prism-okaidia'];
}

function themeCssFor(state) {
    return themeStyles[themeNameFor(state)] || prismOkaidiaThemeCss;
}

function fontSizeFor(state) {
    return `${Number.parseInt(state.scriptEditorPreferences?.fontSize, 10) || 14}px`;
}

function normalizeText(text) {
    return text.replace(/\r\n?/g, '\n').replace(/\u00a0/g, ' ');
}

function lineNumberText(value) {
    const lineCount = Math.max(1, value.split('\n').length);
    return Array.from({length: lineCount}, (_, index) => String(index + 1)).join('\n');
}

function textNodes(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let node = walker.nextNode();
    while (node) {
        nodes.push(node);
        node = walker.nextNode();
    }
    return nodes;
}

function selectionOffsets(root) {
    const selection = root.getRootNode().getSelection?.() || window.getSelection();
    if (!selection || !selection.rangeCount) {
        return null;
    }

    const range = selection.getRangeAt(0);
    if (!root.contains(range.startContainer) || !root.contains(range.endContainer)) {
        return null;
    }

    let start = 0;
    let end = 0;
    let seenStart = false;
    let seenEnd = false;
    for (const node of textNodes(root)) {
        if (node === range.startContainer) {
            start += range.startOffset;
            seenStart = true;
        } else if (!seenStart) {
            start += node.nodeValue.length;
        }

        if (node === range.endContainer) {
            end += range.endOffset;
            seenEnd = true;
        } else if (!seenEnd) {
            end += node.nodeValue.length;
        }

        if (seenStart && seenEnd) {
            break;
        }
    }

    return {
        start,
        end,
        backward: selection.anchorNode === range.endContainer && selection.anchorOffset === range.endOffset,
    };
}

function setPoint(root, offset) {
    let remaining = Math.max(0, offset);
    const nodes = textNodes(root);
    for (const node of nodes) {
        const length = node.nodeValue.length;
        if (remaining <= length) {
            return {node, offset: remaining};
        }
        remaining -= length;
    }

    const fallback = nodes[nodes.length - 1] || root;
    return {
        node: fallback,
        offset: fallback.nodeType === Node.TEXT_NODE ? fallback.nodeValue.length : fallback.childNodes.length,
    };
}

function restoreSelection(root, offsets) {
    if (!offsets) {
        return;
    }

    const selection = root.getRootNode().getSelection?.() || window.getSelection();
    if (!selection) {
        return;
    }

    const start = setPoint(root, offsets.start);
    const end = setPoint(root, offsets.end);
    const range = document.createRange();
    range.setStart(start.node, start.offset);
    range.setEnd(end.node, end.offset);
    selection.removeAllRanges();
    selection.addRange(range);
    if (offsets.backward && selection.extend) {
        selection.collapse(end.node, end.offset);
        selection.extend(start.node, start.offset);
    }
}

function renderHighlighted(value, offsets = null) {
    if (!editor) {
        return;
    }

    editor.value = value;
    editor.input.innerHTML = highlightText(value || '\n', 'python');
    editor.gutter.textContent = lineNumberText(value);
    restoreSelection(editor.input, offsets);
}

function applyPresentation(state) {
    if (!editor) {
        return;
    }

    const theme = themeFor(state);
    editor.root.style.setProperty('--editor-bg', theme.background);
    editor.root.style.setProperty('--editor-fg', theme.foreground);
    editor.root.style.setProperty('--editor-gutter', theme.gutter);
    editor.root.style.setProperty('--editor-gutter-bg', theme.gutterBackground);
    editor.root.style.setProperty('--editor-border', theme.border);
    editor.root.style.setProperty('--editor-selection', theme.selection);
    editor.root.style.setProperty('--editor-caret', theme.caret);
    editor.root.style.setProperty('--editor-font-size', fontSizeFor(state));
    editor.themeStyle.textContent = themeCssFor(state);
    editor.input.contentEditable = isReadOnly(state) ? 'false' : 'true';
    editor.input.classList.toggle('is-readonly', isReadOnly(state));
}

function syncGutter() {
    if (!editor) {
        return;
    }
    editor.gutter.scrollTop = editor.scroll.scrollTop;
}

function insertText(text) {
    const selection = editor.input.getRootNode().getSelection?.() || window.getSelection();
    if (!selection || !selection.rangeCount) {
        return;
    }
    const range = selection.getRangeAt(0);
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
    range.collapse(false);
    selection.removeAllRanges();
    selection.addRange(range);
}

function createHighlightedEditor(host, state) {
    const shadow = host.shadowRoot || host.attachShadow({mode: 'open'});
    const style = document.createElement('style');
    const themeStyle = document.createElement('style');
    const root = document.createElement('div');
    const gutter = document.createElement('pre');
    const scroll = document.createElement('div');
    const input = document.createElement('div');

    style.textContent = editorCss;
    root.className = 'script-code-editor';
    gutter.className = 'script-code-editor__gutter';
    scroll.className = 'script-code-editor__scroll';
    input.className = 'script-code-editor__input language-python';
    input.spellcheck = false;
    input.setAttribute('role', 'textbox');
    input.setAttribute('aria-label', 'Starlark source editor');
    input.setAttribute('aria-multiline', 'true');

    scroll.append(input);
    root.append(gutter, scroll);
    shadow.replaceChildren(style, themeStyle, root);

    editor = {
        host,
        root,
        themeStyle,
        gutter,
        scroll,
        input,
        value: '',
        onInput: null,
        onScroll: null,
        onKeyDown: null,
        onPaste: null,
    };

    editor.onInput = () => {
        const offsets = selectionOffsets(input);
        const value = normalizeText(input.innerText);
        state.scriptEditor.source = value;
        state.storedScriptsError = '';
        state.storedScriptNotice = '';
        renderHighlighted(value, offsets);
    };
    editor.onScroll = syncGutter;
    editor.onKeyDown = (event) => {
        if (event.key === 'Tab') {
            event.preventDefault();
            insertText('    ');
            editor.onInput();
        }
    };
    editor.onPaste = (event) => {
        event.preventDefault();
        insertText(event.clipboardData?.getData('text/plain') || '');
        editor.onInput();
    };

    input.addEventListener('input', editor.onInput);
    input.addEventListener('keydown', editor.onKeyDown);
    input.addEventListener('paste', editor.onPaste);
    scroll.addEventListener('scroll', editor.onScroll, {passive: true});

    applyPresentation(state);
    renderHighlighted(String(state.scriptEditor.source || ''));
}

function destroyEditor() {
    if (editor) {
        editor.input.removeEventListener('input', editor.onInput);
        editor.input.removeEventListener('keydown', editor.onKeyDown);
        editor.input.removeEventListener('paste', editor.onPaste);
        editor.scroll.removeEventListener('scroll', editor.onScroll);
        editor.host?.shadowRoot?.replaceChildren();
    }
    editor = null;
}

function syncEditorValue(state) {
    if (!editor) {
        return;
    }

    const nextValue = String(state.scriptEditor.source || '');
    if (editor.value === nextValue) {
        return;
    }

    const offsets = selectionOffsets(editor.input);
    const scrollTop = editor.scroll.scrollTop;
    const scrollLeft = editor.scroll.scrollLeft;
    renderHighlighted(nextValue, offsets);
    editor.scroll.scrollTop = scrollTop;
    editor.scroll.scrollLeft = scrollLeft;
    syncGutter();
}

export function syncScriptCodeEditor(root, state) {
    const host = root.querySelector('[data-script-code-host]');
    if (!host) {
        destroyEditor();
        return;
    }

    if (!editor || editor.host !== host) {
        destroyEditor();
        createHighlightedEditor(host, state);
    }

    syncEditorValue(state);
    applyPresentation(state);
}
