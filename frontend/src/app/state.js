import {createScriptEditor} from '../scriptModel';
import {createScriptEditorPreferences} from '../scriptEditorOptions';

export const VIEW_HOME = 'home';
export const VIEW_ADOPT_FORM = 'adopt-form';
export const VIEW_ADOPTED_IP = 'adopted-ip';
export const MODULE_STORED_ADOPTIONS = 'stored-adoptions';
export const MODULE_SCRIPTS = 'scripts';
export const ADOPT_MODE_RAW = 'raw';
export const ADOPT_MODE_STORED = 'stored';
export const ADOPTED_TAB_INFO = 'info';
export const ADOPTED_TAB_OPERATIONS = 'operations';
export const ADOPTED_TAB_LOGS = 'logs';
export const DEFAULT_PING_FORM = Object.freeze({
    targetIP: '',
    count: '4',
    payloadHex: '',
});
const SCRIPT_EDITOR_PREFERENCES_STORAGE_KEY = 'kraken.scriptEditorPreferences';

export function createAdoptedEditForm(item = null) {
    if (!item) {
        return {
            label: '',
            currentIP: '',
            interfaceName: '',
            ip: '',
            defaultGateway: '',
            mac: '',
        };
    }

    return {
        label: item.label,
        currentIP: item.ip,
        interfaceName: item.interfaceName,
        ip: item.ip,
        defaultGateway: item.defaultGateway || '',
        mac: item.mac,
    };
}

export function createStoredConfigEditor(config = null) {
    return {
        label: config?.label || '',
        interfaceName: config?.interfaceName || '',
        ip: config?.ip || '',
        defaultGateway: config?.defaultGateway || '',
        mac: config?.mac || '',
    };
}

export function findByField(items, field, value) {
    const normalized = String(value || '').trim();
    if (!normalized) {
        return null;
    }

    return items.find((item) => item[field] === normalized) || null;
}

function sortByField(items, field) {
    return [...items].sort((left, right) => String(left?.[field] || '').localeCompare(String(right?.[field] || ''), undefined, {
        sensitivity: 'base',
    }));
}

function compareIPv4Text(left, right) {
    const leftParts = String(left || '').split('.').map((part) => Number.parseInt(part, 10) || 0);
    const rightParts = String(right || '').split('.').map((part) => Number.parseInt(part, 10) || 0);

    for (let index = 0; index < 4; index += 1) {
        if (leftParts[index] !== rightParts[index]) {
            return leftParts[index] - rightParts[index];
        }
    }

    return 0;
}

export const state = {
    view: VIEW_HOME,
    interfaceSelection: null,
    adoptedItems: [],
    adoptedDetails: null,
    storedConfigs: [],
    storedScripts: [],
    storedConfigsLoaded: false,
    storedScriptsLoaded: false,
    configurationDirectory: '',
    selectedAdoptedIP: '',
    selectedStoredConfigLabel: '',
    selectedStoredScriptName: '',
    adoptMode: ADOPT_MODE_STORED,
    selectedAdoptedTab: ADOPTED_TAB_INFO,
    interfaceSelectionLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    storedScriptsLoading: false,
    interfaceSelectionError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
    storedConfigsError: '',
    storedScriptsError: '',
    configurationDirectoryError: '',
    adopting: false,
    adoptingStoredLabel: '',
    deletingStoredConfigLabel: '',
    deletingStoredScriptName: '',
    pingingAdoptedIP: false,
    startingAdoptedRecording: false,
    stoppingAdoptedRecording: false,
    updatingAdoption: false,
    deletingAdoption: false,
    clearingAdoptedActivity: false,
    savingStoredConfig: false,
    savingStoredScript: false,
    savingAdoptedScript: false,
    pendingClearAdoptedActivity: '',
    pendingDeleteAdoption: '',
    pendingDeleteStoredConfig: '',
    pendingDeleteStoredScript: '',
    adoptError: '',
    adoptedUpdateError: '',
    storedConfigNotice: '',
    storedScriptNotice: '',
    adoptedScriptError: '',
    adoptedRecordingError: '',
    adoptedRecordingNotice: '',
    pingError: '',
    pingResult: null,
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        defaultGateway: '',
        mac: '',
    },
    adoptedEditForm: createAdoptedEditForm(),
    pingForm: {...DEFAULT_PING_FORM},
    storedConfigEditor: createStoredConfigEditor(),
    scriptEditor: createScriptEditor(),
    scriptEditorPreferences: createScriptEditorPreferences(),
    adoptedScriptName: '',
};

export function loadScriptEditorPreferences() {
    if (typeof window === 'undefined' || !window.localStorage) {
        state.scriptEditorPreferences = createScriptEditorPreferences();
        return;
    }

    try {
        const raw = window.localStorage.getItem(SCRIPT_EDITOR_PREFERENCES_STORAGE_KEY);
        const parsed = raw ? JSON.parse(raw) : null;
        state.scriptEditorPreferences = createScriptEditorPreferences(parsed);
    } catch (error) {
        state.scriptEditorPreferences = createScriptEditorPreferences();
    }
}

export function persistScriptEditorPreferences() {
    if (typeof window === 'undefined' || !window.localStorage) {
        return;
    }

    window.localStorage.setItem(
        SCRIPT_EDITOR_PREFERENCES_STORAGE_KEY,
        JSON.stringify(state.scriptEditorPreferences),
    );
}

function setSelectedStoredItems(items, {itemsKey, field, selectedKey, editorKey, createEditor, sync}) {
    state[itemsKey] = sortByField(items, field);

    if (!state[selectedKey]) {
        sync?.();
        return;
    }

    const selected = findByField(state[itemsKey], field, state[selectedKey]);
    if (selected) {
        state[editorKey] = createEditor(selected);
        return;
    }

    state[selectedKey] = '';
    state[editorKey] = createEditor();
    sync?.();
}

export function setStoredConfigs(items) {
    setSelectedStoredItems(items, {
        itemsKey: 'storedConfigs',
        field: 'label',
        selectedKey: 'selectedStoredConfigLabel',
        editorKey: 'storedConfigEditor',
        createEditor: createStoredConfigEditor,
        sync: syncStoredConfigInterfaceName,
    });
}

export function setStoredScripts(items) {
    state.storedScripts = sortByField(items, 'name');

    if (state.selectedStoredScriptName) {
        const selectedScript = findByField(state.storedScripts, 'name', state.selectedStoredScriptName);
        if (selectedScript) {
            if (!selectedScript.source && state.scriptEditor.name === selectedScript.name) {
                state.scriptEditor = {
                    ...state.scriptEditor,
                    available: Boolean(selectedScript.available),
                    compileError: selectedScript.compileError || '',
                    updatedAt: selectedScript.updatedAt || '',
                };
                return;
            }
            state.scriptEditor = createScriptEditor(selectedScript);
            return;
        }

        state.selectedStoredScriptName = '';
        state.scriptEditor = createScriptEditor();
    }
}

export function upsertByField(items, field, item) {
    return [...items.filter((current) => current[field] !== item[field]), item];
}

export function removeByField(items, field, value) {
    return items.filter((item) => item[field] !== value);
}

export function setAdoptedItems(items) {
    state.adoptedItems = [...items].sort((left, right) => {
        const interfaceCompare = String(left.interfaceName || '').localeCompare(String(right.interfaceName || ''));
        if (interfaceCompare !== 0) {
            return interfaceCompare;
        }

        return compareIPv4Text(left.ip, right.ip);
    });

    if (!state.adoptedItems.some((item) => item.ip === state.selectedAdoptedIP)) {
        state.selectedAdoptedIP = state.adoptedItems[0]?.ip || '';
    }
}

export function upsertAdoptedItem(item, previousIP = '') {
    const nextItems = state.adoptedItems.filter((current) => current.ip !== item.ip && current.ip !== previousIP);
    nextItems.push(item);
    setAdoptedItems(nextItems);
}

export function removeAdoptedItem(ip) {
    setAdoptedItems(state.adoptedItems.filter((item) => item.ip !== ip));
}

export function availableInterfaceOptions(requiredName = '') {
    const items = (state.interfaceSelection?.options ?? []).filter((item) => item.canAdopt);

    if (requiredName && !items.some((item) => item.name === requiredName)) {
        const fallback = (state.interfaceSelection?.options ?? []).find((item) => item.name === requiredName);
        if (fallback) {
            items.unshift(fallback);
        }
    }

    return items;
}

export function syncAdoptFormInterfaceName() {
    const items = availableInterfaceOptions();

    if (!items.length) {
        state.adoptForm.interfaceName = '';
        return;
    }

    if (!items.some((item) => item.name === state.adoptForm.interfaceName)) {
        state.adoptForm.interfaceName = items[0].name;
    }
}

export function syncStoredConfigInterfaceName() {
    const items = availableInterfaceOptions(state.storedConfigEditor.interfaceName);

    if (!items.length) {
        state.storedConfigEditor.interfaceName = '';
        return;
    }

    if (!items.some((item) => item.name === state.storedConfigEditor.interfaceName)) {
        state.storedConfigEditor.interfaceName = items[0].name;
    }
}

export function getSelectedAdoptedIPAddress() {
    return state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null;
}

export function getSelectedAdoptedIPAddressDetails() {
    if (state.adoptedDetails?.ip !== state.selectedAdoptedIP) {
        return null;
    }

    return state.adoptedDetails;
}

export function populateAdoptedEditForm(item) {
    state.adoptedEditForm = createAdoptedEditForm(item);
}

export function populateAdoptedScriptName(details) {
    state.adoptedScriptName = details?.scriptName || '';
}

export function resetAdoptedInteractionState() {
    state.pendingClearAdoptedActivity = '';
    state.pendingDeleteAdoption = '';
    state.adoptedUpdateError = '';
    state.adoptedDetailsError = '';
    state.adoptedScriptError = '';
    state.adoptedRecordingError = '';
    state.adoptedRecordingNotice = '';
    state.startingAdoptedRecording = false;
    state.stoppingAdoptedRecording = false;
    state.pingError = '';
    state.pingResult = null;
}

export function resetAdoptedViewState(item = null) {
    state.selectedAdoptedTab = ADOPTED_TAB_INFO;
    state.adoptedDetails = null;
    state.pingForm = {...DEFAULT_PING_FORM};
    resetAdoptedInteractionState();
    populateAdoptedScriptName(null);
    populateAdoptedEditForm(item);
}

export function clearSelectedAdoptedIPAddress() {
    state.selectedAdoptedIP = '';
    resetAdoptedViewState();
}
