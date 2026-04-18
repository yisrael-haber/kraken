import {
    createScriptEditor,
    SCRIPT_SURFACE_PACKET,
} from '../scriptModel';
import {createScriptEditorPreferences} from '../scriptEditorOptions';

export const VIEW_HOME = 'home';
export const VIEW_ADOPT_FORM = 'adopt-form';
export const VIEW_ADOPTED_IP = 'adopted-ip';
export const MODULE_STORED_ADOPTIONS = 'stored-adoptions';
export const MODULE_ROUTING = 'routing';
export const MODULE_SCRIPTS = 'scripts';
export const ADOPT_MODE_RAW = 'raw';
export const ADOPT_MODE_STORED = 'stored';
export const ADOPTED_TAB_INFO = 'info';
export const ADOPTED_TAB_OPERATIONS = 'operations';
export const ADOPTED_TAB_SERVICES = 'services';
export const ADOPTED_SERVICES_VIEW_NEW = 'new';
export const ADOPTED_SERVICES_VIEW_LIVE = 'live';
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
            mtu: '',
            mac: '',
        };
    }

    return {
        label: item.label,
        currentIP: item.ip,
        interfaceName: item.interfaceName,
        ip: item.ip,
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
        defaultGateway: config?.defaultGateway || '',
        mtu: config?.mtu ? String(config.mtu) : '',
        mac: config?.mac || '',
    };
}

export function createStoredRouteEditor(route = null) {
    return {
        label: route?.label || '',
        destinationCIDR: route?.destinationCIDR || '',
        viaAdoptedIP: route?.viaAdoptedIP || '',
        scriptName: route?.scriptName || '',
    };
}

export function findAdoptedService(details, service) {
    return (details?.services || []).find((item) => item.service === service) || null;
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

function defaultServiceFieldValue(definition, field) {
    if (field?.defaultValue) {
        return String(field.defaultValue);
    }
    if (field?.name === 'port' && definition?.defaultPort) {
        return String(definition.defaultPort);
    }

    return '';
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

export function storedScriptKey(itemOrName, surface = SCRIPT_SURFACE_PACKET) {
    const name = typeof itemOrName === 'string'
        ? String(itemOrName || '').trim()
        : String(itemOrName?.name || '').trim();
    const selectedSurface = typeof itemOrName === 'string'
        ? String(surface || SCRIPT_SURFACE_PACKET).trim()
        : String(itemOrName?.surface || SCRIPT_SURFACE_PACKET).trim();

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
            surface: SCRIPT_SURFACE_PACKET,
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

function routePrefixLength(cidr) {
    const separator = String(cidr || '').lastIndexOf('/');
    if (separator < 0) {
        return -1;
    }

    const bits = Number.parseInt(String(cidr).slice(separator + 1), 10);
    return Number.isInteger(bits) ? bits : -1;
}

function normalizeStoredRoutes(items) {
    return [...normalizeItems(items)].sort((left, right) => {
        const prefixCompare = routePrefixLength(right.destinationCIDR) - routePrefixLength(left.destinationCIDR);
        if (prefixCompare !== 0) {
            return prefixCompare;
        }

        const cidrCompare = String(left.destinationCIDR || '').localeCompare(String(right.destinationCIDR || ''));
        if (cidrCompare !== 0) {
            return cidrCompare;
        }

        return String(left.label || '').localeCompare(String(right.label || ''), undefined, {
            sensitivity: 'base',
        });
    });
}

export const state = {
    view: VIEW_HOME,
    interfaceSelection: null,
    adoptedItems: [],
    adoptedDetails: null,
    serviceDefinitions: [],
    storedConfigs: [],
    storedRoutes: [],
    storedScripts: [],
    serviceDefinitionsLoaded: false,
    storedConfigsLoaded: false,
    storedRoutesLoaded: false,
    storedScriptsLoaded: false,
    configurationDirectory: '',
    selectedAdoptedIP: '',
    selectedStoredConfigLabel: '',
    selectedStoredRouteLabel: '',
    selectedStoredScriptKey: '',
    selectedStoredScriptSurface: SCRIPT_SURFACE_PACKET,
    adoptMode: ADOPT_MODE_STORED,
    selectedAdoptedTab: ADOPTED_TAB_INFO,
    selectedAdoptedServicesView: ADOPTED_SERVICES_VIEW_NEW,
    selectedAdoptedService: '',
    serviceDefinitionsLoading: false,
    interfaceSelectionLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    storedRoutesLoading: false,
    storedScriptsLoading: false,
    interfaceSelectionError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
    serviceDefinitionsError: '',
    storedConfigsError: '',
    storedRoutesError: '',
    storedScriptsError: '',
    configurationDirectoryError: '',
    adopting: false,
    adoptingStoredLabel: '',
    deletingStoredConfigLabel: '',
    deletingStoredRouteLabel: '',
    deletingStoredScriptName: '',
    pingingAdoptedIP: false,
    startingAdoptedRecording: false,
    stoppingAdoptedRecording: false,
    startingAdoptedService: '',
    stoppingAdoptedService: '',
    updatingAdoption: false,
    deletingAdoption: false,
    savingStoredConfig: false,
    savingStoredRoute: false,
    savingStoredScript: false,
    savingAdoptedScript: false,
    pendingDeleteAdoption: '',
    pendingDeleteStoredConfig: '',
    pendingDeleteStoredRoute: '',
    pendingDeleteStoredScript: '',
    adoptError: '',
    adoptedUpdateError: '',
    storedConfigNotice: '',
    storedRouteNotice: '',
    storedScriptNotice: '',
    adoptedScriptError: '',
    adoptedRecordingError: '',
    adoptedRecordingNotice: '',
    adoptedServiceError: '',
    adoptedServiceNotice: '',
    pingError: '',
    pingResult: null,
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        defaultGateway: '',
        mtu: '',
        mac: '',
    },
    adoptedEditForm: createAdoptedEditForm(),
    adoptedServiceForms: {},
    pingForm: {...DEFAULT_PING_FORM},
    storedConfigEditor: createStoredConfigEditor(),
    storedRouteEditor: createStoredRouteEditor(),
    scriptEditor: createScriptEditor(null, SCRIPT_SURFACE_PACKET),
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

export function setStoredRoutes(items) {
    setSelectedStoredItems(items, {
        itemsKey: 'storedRoutes',
        field: 'label',
        selectedKey: 'selectedStoredRouteLabel',
        editorKey: 'storedRouteEditor',
        createEditor: createStoredRouteEditor,
        normalizeItems: normalizeStoredRoutes,
    });
}

export function setStoredScripts(items) {
    state.storedScripts = normalizeStoredScripts(items);

    if (state.selectedStoredScriptKey) {
        const selectedScript = findByField(state.storedScripts, 'key', state.selectedStoredScriptKey);
        if (selectedScript) {
            state.selectedStoredScriptSurface = selectedScript.surface || SCRIPT_SURFACE_PACKET;
            if (!selectedScript.source && storedScriptKey(state.scriptEditor) === selectedScript.key) {
                state.scriptEditor = {
                    ...state.scriptEditor,
                    available: Boolean(selectedScript.available),
                    compileError: selectedScript.compileError || '',
                    updatedAt: selectedScript.updatedAt || '',
                    surface: selectedScript.surface || SCRIPT_SURFACE_PACKET,
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

export function populateAdoptedServiceForms(details) {
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
    state.pingError = '';
    state.pingResult = null;
}

export function resetAdoptedViewState(item = null) {
    state.selectedAdoptedTab = ADOPTED_TAB_INFO;
    state.selectedAdoptedServicesView = ADOPTED_SERVICES_VIEW_NEW;
    state.selectedAdoptedService = selectDefaultAdoptedService(state.serviceDefinitions);
    state.adoptedDetails = null;
    state.pingForm = {...DEFAULT_PING_FORM};
    resetAdoptedInteractionState();
    populateAdoptedScriptName(null);
    populateAdoptedServiceForms(null);
    populateAdoptedEditForm(item);
}

export function clearSelectedAdoptedIPAddress() {
    state.selectedAdoptedIP = '';
    resetAdoptedViewState();
}
