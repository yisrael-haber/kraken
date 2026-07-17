import {createScriptEditor, SCRIPT_KIND_GENERIC, SCRIPT_KIND_TRANSPORT} from '../scriptModel';
import {createScriptEditorPreferences} from '../scriptEditorOptions';

export const VIEW_HOME = 'home';
export const VIEW_ADOPT_FORM = 'adopt-form';
export const VIEW_ADOPTED_IP = 'adopted-ip';
export const MODULE_STORED_ADOPTIONS = 'stored-adoptions';
export const MODULE_TRANSPORT_SCRIPTS = 'transport-scripts';
export const MODULE_GLOBAL_SCRIPTING = 'global-scripting';
export const MODULE_OPERATIONS = 'operations';
export const MODULE_SERVICES = 'services';
export const MODULE_OFFLINE = 'offline';
export const ADOPT_MODE_STORED = 'stored';
export const GLOBAL_SCRIPTING_TAB_EDITOR = 'editor';
export const GLOBAL_SCRIPTING_TAB_RUN = 'run';
const defaultDNSForm = Object.freeze({
    server: '',
    name: '',
    type: 'A',
    transport: 'udp',
    timeoutMillis: '3000',
});
const defaultPingForm = Object.freeze({
    destination: '',
    intervalMillis: '1000',
    timeoutMillis: '1000',
    count: '4',
    payloadSize: '56',
});
const defaultKeytabForm = Object.freeze({
    principal: '',
    realm: '',
    password: '',
    kvno: '1',
    fileName: '',
    encryptionTypes: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
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

export function findServiceDefinition(service) {
    return SERVICE_DEFINITIONS.find((item) => item.service === service) || null;
}

export const SERVICE_DEFINITIONS = Object.freeze([
    {service: 'echo', label: 'Echo', defaults: {port: '7007'}, fields: [
        {name: 'port', label: 'Port', type: 'port', required: true},
    ]},
    {service: 'http', label: 'HTTP', defaults: {port: '8080', protocol: 'http'}, fields: [
        {name: 'port', label: 'Port', type: 'port', required: true},
        {name: 'protocol', label: 'Protocol', type: 'select', required: true, options: [
            {value: 'http', label: 'HTTP'},
            {value: 'https', label: 'HTTPS'},
        ]},
        {name: 'rootDirectory', label: 'Root', type: 'directory', required: true},
    ]},
    {service: 'ssh', label: 'SSH', defaults: {port: '2222', allowPty: 'true'}, fields: [
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

export function createAdoptedServiceForms() {
    return Object.fromEntries(SERVICE_DEFINITIONS.map(({service, defaults}) => [service, {...defaults}]));
}

export function selectDefaultAdoptedService(currentService = '') {
    if (currentService && findServiceDefinition(currentService)) {
        return currentService;
    }

    return 'http';
}

export function findByField(items, field, value) {
    const normalized = String(value || '').trim();
    if (!normalized) {
        return null;
    }

    return items.find((item) => item[field] === normalized) || null;
}

function sortByField(items, field) {
    return [...items].sort((left, right) => left[field].localeCompare(right[field], undefined, {
        sensitivity: 'base',
    }));
}

function compareIPv4Text(left, right) {
    const leftParts = left.split('.').map(Number);
    const rightParts = right.split('.').map(Number);

    for (let index = 0; index < 4; index += 1) {
        if (leftParts[index] !== rightParts[index]) {
            return leftParts[index] - rightParts[index];
        }
    }

    return 0;
}

function compareStoredScripts(left, right) {
    return left.name.localeCompare(right.name, undefined, {
        sensitivity: 'base',
    });
}

function normalizeStoredScripts(items) {
    return [...items].sort(compareStoredScripts);
}

export const state = {
    view: VIEW_HOME,
    interfaceSelection: null,
    adoptedItems: [],
    adoptedDetails: null,
    storedConfigs: [],
    storedScripts: [],
    genericScripts: [],
    storedConfigsLoaded: false,
    storedScriptsLoaded: false,
    genericScriptsLoaded: false,
    configurationDirectory: '',
    selectedAdoptedIP: '',
    selectedStoredConfigLabel: '',
    selectedStoredScriptKey: '',
    selectedGenericScriptKey: '',
    selectedOperationSourceIP: '',
    selectedServiceSourceIP: '',
    activeScriptKind: SCRIPT_KIND_TRANSPORT,
    adoptMode: ADOPT_MODE_STORED,
    selectedGlobalScriptingTab: GLOBAL_SCRIPTING_TAB_EDITOR,
    selectedAdoptedService: selectDefaultAdoptedService(),
    interfaceSelectionLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    storedScriptsLoading: false,
    genericScriptsLoading: false,
    interfaceSelectionError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
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
    pinging: false,
    startingAdoptedRecording: false,
    stoppingAdoptedRecording: false,
    startingAdoptedService: '',
    stoppingAdoptedService: '',
    updatingAdoptedMTU: false,
    deletingAdoption: false,
    savingStoredConfig: false,
    savingStoredScript: false,
    savingAdoptedScript: false,
    creatingKeytab: false,
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
    pingError: '',
    pingResult: null,
    keytabError: '',
    keytabResult: null,
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        subnetPrefix: '24',
        defaultGateway: '',
        mtu: '',
        mac: '',
    },
    adoptedServiceForms: createAdoptedServiceForms(),
    dnsForm: {...defaultDNSForm},
    pingForm: {...defaultPingForm},
    keytabForm: {...defaultKeytabForm},
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
        sync: () => syncInterfaceName(state.storedConfigEditor),
    });
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
    return [...items.filter((current) => current[field] !== item[field]), item];
}

export function removeByField(items, field, value) {
    return items.filter((item) => item[field] !== value);
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
    state.adoptedItems = [...items].sort((left, right) => {
        const interfaceCompare = left.interfaceName.localeCompare(right.interfaceName);
        if (interfaceCompare !== 0) {
            return interfaceCompare;
        }

        return compareIPv4Text(left.ip, right.ip);
    });

    if (!state.adoptedItems.some((item) => item.ip === state.selectedAdoptedIP)) {
        state.selectedAdoptedIP = state.adoptedItems[0]?.ip || '';
    }
    if (!state.adoptedItems.some((item) => item.ip === state.selectedOperationSourceIP)) {
        state.selectedOperationSourceIP = state.adoptedItems[0]?.ip || '';
    }
    if (!state.adoptedItems.some((item) => item.ip === state.selectedServiceSourceIP)) {
        state.selectedServiceSourceIP = state.adoptedItems[0]?.ip || '';
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
    return state.interfaceSelection?.options || [];
}

export function syncInterfaceName(form) {
    const items = availableInterfaceOptions();

    if (!items.length) {
        form.interfaceName = '';
        return;
    }

    if (!items.includes(form.interfaceName)) {
        form.interfaceName = items[0];
    }
}

export function populateAdoptedScriptName(details) {
    state.adoptedTransportScriptName = details?.transportScriptName || '';
}

export function populateAdoptedServiceForms() {
    state.adoptedServiceForms = createAdoptedServiceForms();
    state.selectedAdoptedService = selectDefaultAdoptedService(state.selectedAdoptedService);
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
    state.pinging = false;
    state.pingError = '';
    state.pingResult = null;
}

export function resetAdoptedViewState() {
    state.adoptedDetails = null;
    resetAdoptedInteractionState();
    populateAdoptedScriptName(null);
}

export function clearSelectedAdoptedIPAddress() {
    state.selectedAdoptedIP = '';
    resetAdoptedViewState();
}
