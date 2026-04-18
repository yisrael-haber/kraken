export const SCRIPT_EDITOR_THEME_OPTIONS = [
    {value: 'prism-okaidia', label: 'Okaidia'},
    {value: 'github-dark', label: 'GitHub Dark'},
    {value: 'github-dark-dimmed', label: 'GitHub Dark Dimmed'},
    {value: 'solarized-dark-atom', label: 'Solarized Dark Atom'},
];

export const SCRIPT_EDITOR_FONT_SIZE_MIN = 8;
export const SCRIPT_EDITOR_FONT_SIZE_MAX = 20;
export const SCRIPT_EDITOR_FONT_SIZE_DEFAULT = 14;
export const SCRIPT_EDITOR_FONT_SIZE_OPTIONS = Array.from(
    {length: SCRIPT_EDITOR_FONT_SIZE_MAX - SCRIPT_EDITOR_FONT_SIZE_MIN + 1},
    (_, index) => {
        const value = String(SCRIPT_EDITOR_FONT_SIZE_MIN + index);
        return {value, label: `${value} px`};
    },
);

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
