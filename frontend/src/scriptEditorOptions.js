export const SCRIPT_EDITOR_THEME_OPTIONS = [
    {value: 'prism-okaidia', label: 'Okaidia'},
    {value: 'github-dark', label: 'GitHub Dark'},
    {value: 'github-dark-dimmed', label: 'GitHub Dark Dimmed'},
    {value: 'solarized-dark-atom', label: 'Solarized Dark Atom'},
];

export const SCRIPT_EDITOR_FONT_SIZE_MIN = 12;
export const SCRIPT_EDITOR_FONT_SIZE_MAX = 24;
export const SCRIPT_EDITOR_FONT_SIZE_DEFAULT = 14;
export const SCRIPT_EDITOR_FONT_SIZE_OPTIONS = [
    {value: '12', label: '12 px'},
    {value: '13', label: '13 px'},
    {value: '14', label: '14 px'},
    {value: '15', label: '15 px'},
    {value: '16', label: '16 px'},
    {value: '18', label: '18 px'},
    {value: '20', label: '20 px'},
    {value: '22', label: '22 px'},
    {value: '24', label: '24 px'},
];

export function createScriptEditorPreferences(value = null) {
    const source = value || {};
    const validTheme = SCRIPT_EDITOR_THEME_OPTIONS.some((item) => item.value === source.theme)
        ? source.theme
        : 'prism-okaidia';
    const requestedFontSize = Number.parseInt(source.fontSize, 10);
    const validFontSize = Number.isFinite(requestedFontSize)
        ? Math.min(SCRIPT_EDITOR_FONT_SIZE_MAX, Math.max(SCRIPT_EDITOR_FONT_SIZE_MIN, requestedFontSize))
        : SCRIPT_EDITOR_FONT_SIZE_DEFAULT;

    return {
        theme: validTheme,
        fontSize: String(validFontSize),
    };
}
