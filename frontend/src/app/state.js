import {createScriptEditor, SCRIPT_KIND_GENERIC, SCRIPT_KIND_TRANSPORT} from '../scriptModel';
import {createScriptEditorPreferences} from '../scriptEditorOptions';

export const VIEW_HOME = 'home';
export const VIEW_ADOPT_FORM = 'adopt-form';
export const VIEW_ADOPTED_IP = 'adopted-ip';
export const MODULE_STORED_ADOPTIONS = 'stored-adoptions';
export const MODULE_TRANSPORT_SCRIPTS = 'transport-scripts';
export const MODULE_GLOBAL_SCRIPTING = 'global-scripting';
export const ADOPT_MODE_STORED = 'stored';
export const ADOPTED_TAB_INFO = 'info';
export const ADOPTED_TAB_OPERATIONS = 'operations';
export const ADOPTED_TAB_SERVICES = 'services';
export const GLOBAL_SCRIPTING_TAB_EDITOR = 'editor';
export const GLOBAL_SCRIPTING_TAB_RUN = 'run';
export const DEFAULT_DNS_FORM = Object.freeze({
    server: '',
    name: '',
    type: 'A',
    transport: 'udp',
    timeoutMillis: '3000',
});
const SCRIPT_EDITOR_PREFERENCES_STORAGE_KEY = 'kraken.scriptEditorPreferences';

export function createStoredConfigEditor(config = null) {
    return {
        label: config?.label || '',
        interfaceName: config?.interfaceName || '',
        ip: config?.ip || '',
        subnetPrefix: config?.subnetPrefix ? String(config.subnetPrefix) : '24',
        defaultGateway: config?.defaultGateway || '',
        mtu: config?.mtu ? String(config.mtu) : '',
        mac: config?.mac || '',
    };
}

function normalizeServiceDefinitions(items) {
    return normalizeItems(items).map((item) => ({
        ...item,
        fields: normalizeItems(item?.fields),
    }));
}

export function findServiceDefinition(items, service) {
    return normalizeItems(items).find((item) => item.service === service) || null;
}

export const SERVICE_DEFINITIONS = Object.freeze([
    {service: 'echo', label: 'Echo', fields: [
        {name: 'port', label: 'Port', type: 'port', required: true},
    ]},
    {service: 'http', label: 'HTTP', fields: [
        {name: 'port', label: 'Port', type: 'port', required: true},
        {name: 'protocol', label: 'Protocol', type: 'select', required: true, options: [
            {value: 'http', label: 'HTTP'},
            {value: 'https', label: 'HTTPS'},
        ]},
        {name: 'rootDirectory', label: 'Root', type: 'directory', required: true},
    ]},
    {service: 'ssh', label: 'SSH', fields: [
        {name: 'port', label: 'Port', type: 'port', required: true},
        {name: 'username', label: 'User', type: 'text', placeholder: 'researcher'},
        {name: 'password', label: 'Password', type: 'secret', placeholder: 'secret'},
        {name: 'authorizedKey', label: 'Key', type: 'text', placeholder: 'ssh-ed25519 AAAA...'},
        {name: 'allowPty', label: 'Terminal', type: 'select', options: [
            {value: 'true', label: 'On'},
            {value: 'false', label: 'Off'},
        ]},
    ]},
]);

const SERVICE_FORM_DEFAULTS = Object.freeze({
    echo: {port: '7007'},
    http: {port: '8080', protocol: 'http'},
    ssh: {port: '2222', allowPty: 'true'},
});

function defaultServiceFieldValue(definition, field) {
    return SERVICE_FORM_DEFAULTS[definition?.service]?.[field?.name] || '';
}

function createAdoptedServiceForm(definition) {
    const form = {};

    for (const field of normalizeItems(definition?.fields)) {
        form[field.name] = defaultServiceFieldValue(definition, field);
    }

    return form;
}

export function createAdoptedServiceForms(serviceDefinitions = []) {
    const forms = {};

    for (const definition of normalizeServiceDefinitions(serviceDefinitions)) {
        forms[definition.service] = createAdoptedServiceForm(definition);
    };

    return forms;
}

export function selectDefaultAdoptedService(serviceDefinitions, currentService = '') {
    const definitions = normalizeServiceDefinitions(serviceDefinitions);
    if (!definitions.length) {
        return '';
    }
    if (currentService && definitions.some((item) => item.service === currentService)) {
        return currentService;
    }

    return definitions.find((item) => item.service === 'http')?.service || definitions[0].service;
}

export function findByField(items, field, value) {
    const normalized = String(value || '').trim();
    if (!normalized) {
        return null;
    }

    return normalizeItems(items).find((item) => item[field] === normalized) || null;
}

function normalizeItems(items) {
    return Array.isArray(items) ? items : [];
}

function sortByField(items, field) {
    return [...normalizeItems(items)].sort((left, right) => String(left?.[field] || '').localeCompare(String(right?.[field] || ''), undefined, {
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

function compareStoredScripts(left, right) {
    return String(left.name || '').localeCompare(String(right.name || ''), undefined, {
        sensitivity: 'base',
    });
}

function normalizeStoredScripts(items) {
    return normalizeItems(items).sort(compareStoredScripts);
}

export const state = {
    view: VIEW_HOME,
    interfaceSelection: null,
    adoptedItems: [],
    adoptedDetails: null,
    serviceDefinitions: [],
    storedConfigs: [],
    storedScripts: [],
    genericScripts: [],
    serviceDefinitionsLoaded: false,
    storedConfigsLoaded: false,
    storedScriptsLoaded: false,
    genericScriptsLoaded: false,
    configurationDirectory: '',
    selectedAdoptedIP: '',
    selectedStoredConfigLabel: '',
    selectedStoredScriptKey: '',
    selectedGenericScriptKey: '',
    activeScriptKind: SCRIPT_KIND_TRANSPORT,
    adoptMode: ADOPT_MODE_STORED,
    selectedAdoptedTab: ADOPTED_TAB_INFO,
    selectedGlobalScriptingTab: GLOBAL_SCRIPTING_TAB_EDITOR,
    selectedAdoptedService: '',
    serviceDefinitionsLoading: false,
    interfaceSelectionLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    storedScriptsLoading: false,
    genericScriptsLoading: false,
    interfaceSelectionError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
    serviceDefinitionsError: '',
    storedConfigsError: '',
    storedScriptsError: '',
    genericScriptsError: '',
    configurationDirectoryError: '',
    adopting: false,
    adoptingStoredLabel: '',
    deletingStoredConfigLabel: '',
    deletingStoredScriptName: '',
    deletingGenericScriptName: '',
    runningGenericScript: false,
    resolvingAdoptedDNS: false,
    startingAdoptedRecording: false,
    stoppingAdoptedRecording: false,
    startingAdoptedService: '',
    stoppingAdoptedService: '',
    updatingAdoptedMTU: false,
    deletingAdoption: false,
    savingStoredConfig: false,
    savingStoredScript: false,
    savingAdoptedScript: false,
    pendingDeleteAdoption: '',
    pendingDeleteStoredConfig: '',
    pendingDeleteStoredScript: '',
    pendingDeleteGenericScript: '',
    adoptError: '',
    adoptedMTUError: '',
    storedConfigNotice: '',
    storedScriptNotice: '',
    genericScriptNotice: '',
    adoptedScriptError: '',
    genericScriptRunError: '',
    genericScriptRunResult: null,
    adoptedRecordingError: '',
    adoptedRecordingNotice: '',
    adoptedServiceError: '',
    adoptedServiceNotice: '',
    dnsError: '',
    dnsResult: null,
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        subnetPrefix: '24',
        defaultGateway: '',
        mtu: '',
        mac: '',
    },
    adoptedServiceForms: {},
    dnsForm: {...DEFAULT_DNS_FORM},
    storedConfigEditor: createStoredConfigEditor(),
    scriptEditor: createScriptEditor(),
    scriptEditorPreferences: createScriptEditorPreferences(),
    adoptedTransportScriptName: '',
    selectedGenericRunScriptName: '',
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

function setSelectedStoredItems(items, {itemsKey, field, selectedKey, editorKey, createEditor, sync, normalizeItems}) {
    state[itemsKey] = normalizeItems ? normalizeItems(items) : sortByField(items, field);

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

export function setServiceDefinitions(items) {
    state.serviceDefinitions = normalizeServiceDefinitions(items);
    state.selectedAdoptedService = selectDefaultAdoptedService(state.serviceDefinitions, state.selectedAdoptedService);
    state.adoptedServiceForms = createAdoptedServiceForms(state.serviceDefinitions);
}

export function setStoredScripts(items) {
    state.storedScripts = normalizeStoredScripts(items);

    if (state.selectedStoredScriptKey) {
        const selectedScript = findByField(state.storedScripts, 'name', state.selectedStoredScriptKey);
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

        state.selectedStoredScriptKey = '';
        state.scriptEditor = createScriptEditor();
    }
}

export function setGenericScripts(items) {
    state.genericScripts = normalizeStoredScripts(items);

    if (state.selectedGenericScriptKey) {
        const selectedScript = findByField(state.genericScripts, 'name', state.selectedGenericScriptKey);
        if (selectedScript) {
            if (state.activeScriptKind === SCRIPT_KIND_GENERIC) {
                state.scriptEditor = createScriptEditor(selectedScript, SCRIPT_KIND_GENERIC);
            }
            return;
        }

        state.selectedGenericScriptKey = '';
        if (state.activeScriptKind === SCRIPT_KIND_GENERIC) {
            state.scriptEditor = createScriptEditor(null, SCRIPT_KIND_GENERIC);
        }
    }

    if (!state.selectedGenericRunScriptName || !state.genericScripts.some((item) => item.name === state.selectedGenericRunScriptName && item.available)) {
        state.selectedGenericRunScriptName = state.genericScripts.find((item) => item.available)?.name || '';
    }
}

export function upsertByField(items, field, item) {
    return [...normalizeItems(items).filter((current) => current[field] !== item[field]), item];
}

export function removeByField(items, field, value) {
    return normalizeItems(items).filter((item) => item[field] !== value);
}

export function upsertStoredScriptItem(items, item) {
    return upsertByField(items, 'name', item);
}

export function activeScriptState() {
    if (state.activeScriptKind === SCRIPT_KIND_GENERIC) {
        return {
            kind: SCRIPT_KIND_GENERIC,
            itemsKey: 'genericScripts',
            selectedKey: 'selectedGenericScriptKey',
            loadingKey: 'genericScriptsLoading',
            loadedKey: 'genericScriptsLoaded',
            errorKey: 'genericScriptsError',
            noticeKey: 'genericScriptNotice',
            deletingKey: 'deletingGenericScriptName',
            pendingDeleteKey: 'pendingDeleteGenericScript',
        };
    }
    return {
        kind: SCRIPT_KIND_TRANSPORT,
        itemsKey: 'storedScripts',
        selectedKey: 'selectedStoredScriptKey',
        loadingKey: 'storedScriptsLoading',
        loadedKey: 'storedScriptsLoaded',
        errorKey: 'storedScriptsError',
        noticeKey: 'storedScriptNotice',
        deletingKey: 'deletingStoredScriptName',
        pendingDeleteKey: 'pendingDeleteStoredScript',
    };
}

export function appendGenericScriptOutput(stream, text) {
    const key = stream === 'stderr' ? 'stderr' : 'stdout';
    const current = state.genericScriptRunResult || {};
    state.genericScriptRunResult = {
        ...current,
        [key]: `${current[key] || ''}${text || ''}`,
    };
    if (key === 'stderr') {
        state.genericScriptRunError = '';
    }
}

export function setAdoptedItems(items) {
    state.adoptedItems = [...normalizeItems(items)].sort((left, right) => {
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

export function upsertAdoptedItem(item) {
    const nextItems = state.adoptedItems.filter((current) => current.ip !== item.ip);
    nextItems.push(item);
    setAdoptedItems(nextItems);
}

export function removeAdoptedItem(ip) {
    setAdoptedItems(state.adoptedItems.filter((item) => item.ip !== ip));
}

export function availableInterfaceOptions() {
    return [...(state.interfaceSelection?.options ?? [])];
}

export function syncAdoptFormInterfaceName() {
    const items = availableInterfaceOptions();

    if (!items.length) {
        state.adoptForm.interfaceName = '';
        return;
    }

    if (!items.includes(state.adoptForm.interfaceName)) {
        state.adoptForm.interfaceName = items[0];
    }
}

export function syncStoredConfigInterfaceName() {
    const items = availableInterfaceOptions();

    if (!items.length) {
        state.storedConfigEditor.interfaceName = '';
        return;
    }

    if (!items.includes(state.storedConfigEditor.interfaceName)) {
        state.storedConfigEditor.interfaceName = items[0];
    }
}

export function populateAdoptedScriptName(details) {
    state.adoptedTransportScriptName = details?.transportScriptName || '';
}

export function populateAdoptedServiceForms() {
    state.adoptedServiceForms = createAdoptedServiceForms(state.serviceDefinitions);
    state.selectedAdoptedService = selectDefaultAdoptedService(state.serviceDefinitions, state.selectedAdoptedService);
}

export function resetAdoptedInteractionState() {
    state.pendingDeleteAdoption = '';
    state.adoptedMTUError = '';
    state.adoptedDetailsError = '';
    state.adoptedScriptError = '';
    state.adoptedRecordingError = '';
    state.adoptedRecordingNotice = '';
    state.adoptedServiceError = '';
    state.adoptedServiceNotice = '';
    state.startingAdoptedRecording = false;
    state.stoppingAdoptedRecording = false;
    state.startingAdoptedService = '';
    state.stoppingAdoptedService = '';
    state.resolvingAdoptedDNS = false;
    state.dnsError = '';
    state.dnsResult = null;
}

export function resetAdoptedViewState(item = null) {
    state.selectedAdoptedTab = ADOPTED_TAB_INFO;
    state.selectedAdoptedService = selectDefaultAdoptedService(state.serviceDefinitions);
    state.adoptedDetails = null;
    state.dnsForm = {...DEFAULT_DNS_FORM};
    resetAdoptedInteractionState();
    populateAdoptedScriptName(null);
    populateAdoptedServiceForms();
}

export function clearSelectedAdoptedIPAddress() {
    state.selectedAdoptedIP = '';
    resetAdoptedViewState();
}
