import {
    createEmptyAdoptedOverrideBindings,
    createPacketOverrideEditor,
} from '../packetOverrideModel';

export const VIEW_HOME = 'home';
export const VIEW_ADOPT_FORM = 'adopt-form';
export const VIEW_ADOPTED_IP = 'adopted-ip';
export const MODULE_LOCAL_NETWORK = 'local-network';
export const MODULE_PACKET_OVERRIDES = 'packet-overrides';
export const MODULE_STORED_ADOPTIONS = 'stored-adoptions';
export const ADOPT_MODE_RAW = 'raw';
export const ADOPT_MODE_STORED = 'stored';
export const ADOPTED_TAB_INFO = 'info';
export const ADOPTED_TAB_ARP = 'arp';
export const ADOPTED_TAB_ICMP = 'icmp';
export const DEFAULT_PING_FORM = Object.freeze({
    targetIP: '',
    count: '4',
});

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
    snapshot: null,
    adoptedItems: [],
    adoptedDetails: null,
    storedConfigs: [],
    storedOverrides: [],
    storedConfigsLoaded: false,
    storedOverridesLoaded: false,
    selectedName: '',
    selectedAdoptedIP: '',
    selectedStoredConfigLabel: '',
    selectedStoredOverrideName: '',
    adoptMode: ADOPT_MODE_STORED,
    selectedAdoptedTab: ADOPTED_TAB_INFO,
    query: '',
    interfacesLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    storedOverridesLoading: false,
    interfaceError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
    storedConfigsError: '',
    storedOverridesError: '',
    adopting: false,
    adoptingStoredLabel: '',
    deletingStoredConfigLabel: '',
    deletingStoredOverrideName: '',
    pingingAdoptedIP: false,
    updatingAdoption: false,
    deletingAdoption: false,
    clearingAdoptedActivity: false,
    savingStoredConfig: false,
    savingStoredOverride: false,
    savingAdoptedOverrideBindings: false,
    pendingClearAdoptedActivity: '',
    pendingDeleteAdoption: '',
    pendingDeleteStoredConfig: '',
    pendingDeleteStoredOverride: '',
    adoptError: '',
    adoptedUpdateError: '',
    storedConfigNotice: '',
    storedOverrideNotice: '',
    adoptedOverrideBindingsError: '',
    pingError: '',
    pingResult: null,
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        defaultGateway: '',
        mac: '',
    },
    adoptedEditForm: {
        label: '',
        currentIP: '',
        interfaceName: '',
        ip: '',
        defaultGateway: '',
        mac: '',
    },
    pingForm: {...DEFAULT_PING_FORM},
    storedConfigEditor: createStoredConfigEditor(),
    overrideEditor: createPacketOverrideEditor(),
    adoptedOverrideBindingsForm: createEmptyAdoptedOverrideBindings(),
};

export function setStoredConfigs(items) {
    state.storedConfigs = sortByField(items, 'label');

    if (state.selectedStoredConfigLabel) {
        const selectedConfig = findByField(state.storedConfigs, 'label', state.selectedStoredConfigLabel);
        if (selectedConfig) {
            state.storedConfigEditor = createStoredConfigEditor(selectedConfig);
            return;
        }

        state.selectedStoredConfigLabel = '';
        state.storedConfigEditor = createStoredConfigEditor();
    }

    syncStoredConfigEditorInterface();
}

export function setStoredOverrides(items) {
    state.storedOverrides = sortByField(items, 'name');

    if (state.selectedStoredOverrideName) {
        const selectedOverride = findByField(state.storedOverrides, 'name', state.selectedStoredOverrideName);
        if (selectedOverride) {
            state.overrideEditor = createPacketOverrideEditor(selectedOverride);
            return;
        }

        state.selectedStoredOverrideName = '';
        state.overrideEditor = createPacketOverrideEditor();
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

export function filteredInterfaces() {
    const items = state.snapshot?.interfaces ?? [];
    const query = state.query.trim().toLowerCase();

    if (!query) {
        return items;
    }

    return items.filter((item) => {
        const fields = [
            item.name,
            item.description,
            item.hardwareAddr,
            ...(item.systemAddresses ?? []).map((address) => address.address),
            ...(item.captureAddresses ?? []).map((address) => address.address),
            ...(item.osFlags ?? []),
            ...(item.captureFlags ?? []),
        ];

        return fields.some((field) => String(field ?? '').toLowerCase().includes(query));
    });
}

export function adoptableInterfaces(requiredName = '') {
    const items = (state.snapshot?.interfaces ?? []).filter((item) => item.canAdopt);

    if (requiredName && !items.some((item) => item.name === requiredName)) {
        const fallback = (state.snapshot?.interfaces ?? []).find((item) => item.name === requiredName);
        if (fallback) {
            items.unshift(fallback);
        }
    }

    return items;
}

export function syncAdoptionFormInterface() {
    const items = adoptableInterfaces();

    if (!items.length) {
        state.adoptForm.interfaceName = '';
        return;
    }

    if (!items.some((item) => item.name === state.adoptForm.interfaceName)) {
        state.adoptForm.interfaceName = items[0].name;
    }
}

export function syncStoredConfigEditorInterface() {
    const items = adoptableInterfaces(state.storedConfigEditor.interfaceName);

    if (!items.length) {
        state.storedConfigEditor.interfaceName = '';
        return;
    }

    if (!items.some((item) => item.name === state.storedConfigEditor.interfaceName)) {
        state.storedConfigEditor.interfaceName = items[0].name;
    }
}

export function getSelectedInterface(items) {
    return items.find((item) => item.name === state.selectedName) || items[0] || null;
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
    if (!item) {
        state.adoptedEditForm = {
            label: '',
            currentIP: '',
            interfaceName: '',
            ip: '',
            defaultGateway: '',
            mac: '',
        };
        return;
    }

    state.adoptedEditForm = {
        label: item.label,
        currentIP: item.ip,
        interfaceName: item.interfaceName,
        ip: item.ip,
        defaultGateway: item.defaultGateway || '',
        mac: item.mac,
    };
}

export function populateAdoptedOverrideBindings(details) {
    const bindings = details?.overrideBindings || {};

    state.adoptedOverrideBindingsForm = {
        arpRequestOverride: bindings.arpRequestOverride || '',
        arpReplyOverride: bindings.arpReplyOverride || '',
        icmpEchoRequestOverride: bindings.icmpEchoRequestOverride || '',
        icmpEchoReplyOverride: bindings.icmpEchoReplyOverride || '',
    };
}
