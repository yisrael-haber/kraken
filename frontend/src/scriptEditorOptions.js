export const SCRIPT_EDITOR_THEME = 'github-dark-dimmed';
export const SCRIPT_EDITOR_THEME_OPTIONS = [
    {value: 'atom-one-dark', label: 'Atom One Dark'},
    {value: 'dracula', label: 'Dracula'},
    {value: 'github-dark', label: 'GitHub Dark'},
    {value: 'github-dark-dimmed', label: 'GitHub Dark Dimmed'},
    {value: 'github-light', label: 'GitHub Light'},
    {value: 'night-owl', label: 'Night Owl'},
    {value: 'night-owl-light', label: 'Night Owl Light'},
    {value: 'prism', label: 'Prism'},
    {value: 'prism-okaidia', label: 'Okaidia'},
    {value: 'prism-solarized-light', label: 'Solarized Light'},
    {value: 'prism-tomorrow', label: 'Tomorrow'},
    {value: 'prism-twilight', label: 'Twilight'},
    {value: 'vs-code-dark', label: 'VS Code Dark'},
    {value: 'vs-code-light', label: 'VS Code Light'},
];

const scriptEditorFontSizeMin = 8;
const scriptEditorFontSizeMax = 20;
const scriptEditorFontSizeDefault = 14;
export const SCRIPT_EDITOR_FONT_SIZE_OPTIONS = Array.from(
    {length: scriptEditorFontSizeMax - scriptEditorFontSizeMin + 1},
    (_, index) => {
        const value = String(scriptEditorFontSizeMin + index);
        return {value, label: `${value} px`};
    },
);

export function createScriptEditorPreferences(value = null) {
    const source = value || {};
    const validTheme = SCRIPT_EDITOR_THEME_OPTIONS.some((item) => item.value === source.theme)
        ? source.theme
        : SCRIPT_EDITOR_THEME;
    const requestedFontSize = Number.parseInt(source.fontSize, 10);
    const validFontSize = Number.isFinite(requestedFontSize)
        ? Math.min(scriptEditorFontSizeMax, Math.max(scriptEditorFontSizeMin, requestedFontSize))
        : scriptEditorFontSizeDefault;

    return {
        theme: validTheme,
        fontSize: String(validFontSize),
    };
}
