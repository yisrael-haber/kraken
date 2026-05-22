import {
    createScriptEditor,
    SCRIPT_SURFACE_TRANSPORT,
} from '../scriptModel';
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
export const ADOPTED_TAB_SERVICES = 'services';
export const ADOPTED_SERVICES_VIEW_NEW = 'new';
export const ADOPTED_SERVICES_VIEW_LIVE = 'live';
export const DEFAULT_DNS_FORM = Object.freeze({
    server: '',
    name: '',
    type: 'A',
    transport: 'udp',
    timeoutMillis: '3000',
});
const SCRIPT_EDITOR_PREFERENCES_STORAGE_KEY = 'kraken.scriptEditorPreferences';

export function createAdoptedEditForm(item = null) {
    if (!item) {
        return {
            label: '',
            currentIP: '',
            interfaceName: '',
            ip: '',
            subnetMask: '255.255.255.0',
            defaultGateway: '',
            mtu: '',
            mac: '',
        };
    }

    return {
        label: item.label,
        currentIP: item.ip,
        interfaceName: item.interfaceName,
        ip: item.ip,
        subnetMask: item.subnetMask || '255.255.255.0',
        defaultGateway: item.defaultGateway || '',
        mtu: item.mtu ? String(item.mtu) : '',
        mac: item.mac,
    };
}

export function createStoredConfigEditor(config = null) {
    return {
        label: config?.label || '',
        interfaceName: config?.interfaceName || '',
        ip: config?.ip || '',
        subnetMask: config?.subnetMask || '255.255.255.0',
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

export function storedScriptKey(itemOrName, surface = SCRIPT_SURFACE_TRANSPORT) {
    const name = typeof itemOrName === 'string'
        ? String(itemOrName || '').trim()
        : String(itemOrName?.name || '').trim();
    const selectedSurface = typeof itemOrName === 'string'
        ? String(surface || SCRIPT_SURFACE_TRANSPORT).trim()
        : String(itemOrName?.surface || SCRIPT_SURFACE_TRANSPORT).trim();

    if (!name) {
        return '';
    }

    return `${selectedSurface}:${name}`;
}

export function parseStoredScriptKey(value) {
    const normalized = String(value || '').trim();
    const separator = normalized.indexOf(':');
    if (separator <= 0) {
        return {
            name: normalized,
            surface: SCRIPT_SURFACE_TRANSPORT,
        };
    }

    return {
        surface: normalized.slice(0, separator),
        name: normalized.slice(separator + 1),
    };
}

function compareStoredScripts(left, right) {
    const surfaceCompare = String(left.surface || '').localeCompare(String(right.surface || ''));
    if (surfaceCompare !== 0) {
        return surfaceCompare;
    }
    return String(left.name || '').localeCompare(String(right.name || ''), undefined, {
        sensitivity: 'base',
    });
}

function normalizeStoredScripts(items) {
    return normalizeItems(items).map((item) => ({
        ...item,
        key: storedScriptKey(item),
    })).sort(compareStoredScripts);
}

export const state = {
    view: VIEW_HOME,
    interfaceSelection: null,
    adoptedItems: [],
    adoptedDetails: null,
    serviceDefinitions: [],
    storedConfigs: [],
    storedScripts: [],
    serviceDefinitionsLoaded: false,
    storedConfigsLoaded: false,
    storedScriptsLoaded: false,
    configurationDirectory: '',
    selectedAdoptedIP: '',
    selectedStoredConfigLabel: '',
    selectedStoredScriptKey: '',
    selectedStoredScriptSurface: SCRIPT_SURFACE_TRANSPORT,
    adoptMode: ADOPT_MODE_STORED,
    selectedAdoptedTab: ADOPTED_TAB_INFO,
    selectedAdoptedServicesView: ADOPTED_SERVICES_VIEW_NEW,
    selectedAdoptedService: '',
    serviceDefinitionsLoading: false,
    interfaceSelectionLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    storedScriptsLoading: false,
    interfaceSelectionError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
    serviceDefinitionsError: '',
    storedConfigsError: '',
    storedScriptsError: '',
    configurationDirectoryError: '',
    adopting: false,
    adoptingStoredLabel: '',
    deletingStoredConfigLabel: '',
    deletingStoredScriptName: '',
    resolvingAdoptedDNS: false,
    startingAdoptedRecording: false,
    stoppingAdoptedRecording: false,
    startingAdoptedService: '',
    stoppingAdoptedService: '',
    updatingAdoption: false,
    deletingAdoption: false,
    savingStoredConfig: false,
    savingStoredScript: false,
    savingAdoptedScript: false,
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
    adoptedServiceError: '',
    adoptedServiceNotice: '',
    dnsError: '',
    dnsResult: null,
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        subnetMask: '255.255.255.0',
        defaultGateway: '',
        mtu: '',
        mac: '',
    },
    adoptedEditForm: createAdoptedEditForm(),
    adoptedServiceForms: {},
    dnsForm: {...DEFAULT_DNS_FORM},
    storedConfigEditor: createStoredConfigEditor(),
    scriptEditor: createScriptEditor(null, SCRIPT_SURFACE_TRANSPORT),
    scriptEditorPreferences: createScriptEditorPreferences(),
    adoptedTransportScriptName: '',
    adoptedApplicationScriptName: '',
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
        const selectedScript = findByField(state.storedScripts, 'key', state.selectedStoredScriptKey);
        if (selectedScript) {
            state.selectedStoredScriptSurface = selectedScript.surface || SCRIPT_SURFACE_TRANSPORT;
            if (!selectedScript.source && storedScriptKey(state.scriptEditor) === selectedScript.key) {
                state.scriptEditor = {
                    ...state.scriptEditor,
                    available: Boolean(selectedScript.available),
                    compileError: selectedScript.compileError || '',
                    updatedAt: selectedScript.updatedAt || '',
                    surface: selectedScript.surface || SCRIPT_SURFACE_TRANSPORT,
                };
                return;
            }
            state.scriptEditor = createScriptEditor(selectedScript);
            return;
        }

        state.selectedStoredScriptKey = '';
        state.scriptEditor = createScriptEditor(null, state.selectedStoredScriptSurface);
    }
}

export function upsertByField(items, field, item) {
    return [...normalizeItems(items).filter((current) => current[field] !== item[field]), item];
}

export function removeByField(items, field, value) {
    return normalizeItems(items).filter((item) => item[field] !== value);
}

export function upsertStoredScriptItem(items, item) {
    const key = storedScriptKey(item);
    const next = items.filter((current) => storedScriptKey(current) !== key);
    next.push(item);
    return next;
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

export function upsertAdoptedItem(item, previousIP = '') {
    const nextItems = state.adoptedItems.filter((current) => current.ip !== item.ip && current.ip !== previousIP);
    nextItems.push(item);
    setAdoptedItems(nextItems);
}

export function removeAdoptedItem(ip) {
    setAdoptedItems(state.adoptedItems.filter((item) => item.ip !== ip));
}

export function availableInterfaceOptions(requiredName = '') {
    const items = [...(state.interfaceSelection?.options ?? [])];

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

export function populateAdoptedEditForm(item) {
    state.adoptedEditForm = createAdoptedEditForm(item);
}

export function populateAdoptedScriptName(details) {
    state.adoptedTransportScriptName = details?.transportScriptName || '';
    state.adoptedApplicationScriptName = details?.applicationScriptName || '';
}

export function populateAdoptedServiceForms() {
    state.adoptedServiceForms = createAdoptedServiceForms(state.serviceDefinitions);
    state.selectedAdoptedService = selectDefaultAdoptedService(state.serviceDefinitions, state.selectedAdoptedService);
}

export function resetAdoptedInteractionState() {
    state.pendingDeleteAdoption = '';
    state.adoptedUpdateError = '';
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
    state.selectedAdoptedServicesView = ADOPTED_SERVICES_VIEW_NEW;
    state.selectedAdoptedService = selectDefaultAdoptedService(state.serviceDefinitions);
    state.adoptedDetails = null;
    state.dnsForm = {...DEFAULT_DNS_FORM};
    resetAdoptedInteractionState();
    populateAdoptedScriptName(null);
    populateAdoptedServiceForms();
    populateAdoptedEditForm(item);
}

export function clearSelectedAdoptedIPAddress() {
    state.selectedAdoptedIP = '';
    resetAdoptedViewState();
}
