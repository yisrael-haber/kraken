import './style.css';
import './app.css';

import logo from './assets/images/kraken_logo.png';
import {
    buildStoredPacketOverridePayload,
    createEmptyAdoptedOverrideBindings,
    createPacketOverrideEditor,
    defaultOverrideFieldValue,
    PACKET_OVERRIDE_SCHEMA,
} from './packetOverrideModel';
import {renderAdoptIPAddressForm, renderAdoptedIPAddressView} from './ui/adoption';
import {renderModuleHome} from './ui/home';
import {renderLocalNetworkModule} from './ui/localNetwork';
import {renderPacketOverridesModule} from './ui/overrides';
import {renderStoredAdoptionsModule} from './ui/storedAdoptions';
import {
    AdoptIPAddress,
    AdoptStoredAdoptionConfiguration,
    ClearAdoptedIPAddressActivity,
    DeleteStoredAdoptionConfiguration,
    DeleteStoredPacketOverride,
    GetAdoptedIPAddressDetails,
    ListAdoptedIPAddresses,
    ListInterfaces,
    ListStoredAdoptionConfigurations,
    ListStoredPacketOverrides,
    PingAdoptedIPAddress,
    ReleaseIPAddress,
    SaveStoredAdoptionConfiguration,
    SaveStoredPacketOverride,
    UpdateAdoptedIPAddressOverrideBindings,
    UpdateAdoptedIPAddress,
} from '../wailsjs/go/main/App';

const VIEW_HOME = 'home';
const VIEW_ADOPT_FORM = 'adopt-form';
const VIEW_ADOPTED_IP = 'adopted-ip';
const MODULE_LOCAL_NETWORK = 'local-network';
const MODULE_PACKET_OVERRIDES = 'packet-overrides';
const MODULE_STORED_ADOPTIONS = 'stored-adoptions';
const ADOPT_MODE_RAW = 'raw';
const ADOPT_MODE_STORED = 'stored';
const ADOPTED_TAB_INFO = 'info';
const ADOPTED_TAB_ARP = 'arp';
const ADOPTED_TAB_ICMP = 'icmp';
const DEFAULT_PING_FORM = Object.freeze({
    targetIP: '',
    count: '4',
});

function createStoredConfigEditor(config = null) {
    return {
        label: config?.label || '',
        interfaceName: config?.interfaceName || '',
        ip: config?.ip || '',
        defaultGateway: config?.defaultGateway || '',
        mac: config?.mac || '',
    };
}

function findByField(items, field, value) {
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

function setStoredConfigs(items) {
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

function setStoredOverrides(items) {
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

function upsertByField(items, field, item) {
    return [...items.filter((current) => current[field] !== item[field]), item];
}

function removeByField(items, field, value) {
    return items.filter((item) => item[field] !== value);
}

function setAdoptedItems(items) {
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

function upsertAdoptedItem(item, previousIP = '') {
    const nextItems = state.adoptedItems.filter((current) => current.ip !== item.ip && current.ip !== previousIP);
    nextItems.push(item);
    setAdoptedItems(nextItems);
}

function removeAdoptedItem(ip) {
    setAdoptedItems(state.adoptedItems.filter((item) => item.ip !== ip));
}

async function loadStoredItems(options, {loadingKey, errorKey, loadedKey}, loader, setter) {
    state[loadingKey] = true;
    state[errorKey] = '';

    if (options.render !== false) {
        render();
    }

    try {
        setter(await loader());
        state[loadedKey] = true;
    } catch (error) {
        state[errorKey] = error?.message || String(error);
    } finally {
        state[loadingKey] = false;

        if (options.render !== false) {
            render();
        }
    }
}

async function deleteStoredItem(value, keys, request, onSuccess) {
    const {busyKey, pendingKey, errorKey, noticeKey} = keys;
    if (!value || state[busyKey]) {
        return;
    }

    state[busyKey] = value;
    state[pendingKey] = '';
    state[errorKey] = '';
    state[noticeKey] = '';
    render();

    try {
        await request(value);
        onSuccess(value);
    } catch (error) {
        state[errorKey] = error?.message || String(error);
    } finally {
        state[busyKey] = '';
        render();
    }
}

const state = {
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

const root = document.querySelector('#app');

function filteredInterfaces() {
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

function adoptableInterfaces(requiredName = '') {
    const items = (state.snapshot?.interfaces ?? []).filter((item) => item.canAdopt);

    if (requiredName && !items.some((item) => item.name === requiredName)) {
        const fallback = (state.snapshot?.interfaces ?? []).find((item) => item.name === requiredName);
        if (fallback) {
            items.unshift(fallback);
        }
    }

    return items;
}

function syncAdoptionFormInterface() {
    const items = adoptableInterfaces();

    if (!items.length) {
        state.adoptForm.interfaceName = '';
        return;
    }

    if (!items.some((item) => item.name === state.adoptForm.interfaceName)) {
        state.adoptForm.interfaceName = items[0].name;
    }
}

function syncStoredConfigEditorInterface() {
    const items = adoptableInterfaces(state.storedConfigEditor.interfaceName);

    if (!items.length) {
        state.storedConfigEditor.interfaceName = '';
        return;
    }

    if (!items.some((item) => item.name === state.storedConfigEditor.interfaceName)) {
        state.storedConfigEditor.interfaceName = items[0].name;
    }
}

function ensureLoaded(loadedKey, loadingKey, loader, options = {}) {
    if (!state[loadedKey] && !state[loadingKey]) {
        loader(options);
    }
}

function ensureInterfacesLoaded(options = {}) {
    if (!state.snapshot && !state.interfacesLoading) {
        loadInterfaces(options);
    }
}

function getSelectedInterface(items) {
    return items.find((item) => item.name === state.selectedName) || items[0] || null;
}

function getSelectedAdoptedIPAddress() {
    return state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null;
}

function getSelectedAdoptedIPAddressDetails() {
    if (state.adoptedDetails?.ip !== state.selectedAdoptedIP) {
        return null;
    }

    return state.adoptedDetails;
}

function populateAdoptedEditForm(item) {
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

function populateAdoptedOverrideBindings(details) {
    const bindings = details?.overrideBindings || {};

    state.adoptedOverrideBindingsForm = {
        arpRequestOverride: bindings.arpRequestOverride || '',
        arpReplyOverride: bindings.arpReplyOverride || '',
        icmpEchoRequestOverride: bindings.icmpEchoRequestOverride || '',
        icmpEchoReplyOverride: bindings.icmpEchoReplyOverride || '',
    };
}

function openModule(moduleName) {
    state.view = moduleName;

    if (moduleName === MODULE_LOCAL_NETWORK) {
        ensureInterfacesLoaded();
        return;
    }

    if (moduleName === MODULE_STORED_ADOPTIONS) {
        syncStoredConfigEditorInterface();
        render();

        ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', loadStoredAdoptionConfigurations);
        ensureInterfacesLoaded();
        return;
    }

    if (moduleName === MODULE_PACKET_OVERRIDES) {
        render();
        ensureLoaded('storedOverridesLoaded', 'storedOverridesLoading', loadStoredPacketOverrides);
        return;
    }

    render();
}

function openAdoptForm() {
    state.view = VIEW_ADOPT_FORM;
    state.adoptMode = ADOPT_MODE_STORED;
    state.adoptError = '';
    state.storedConfigsError = '';
    syncAdoptionFormInterface();
    render();

    ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', loadStoredAdoptionConfigurations);
    ensureInterfacesLoaded();
}

async function openAdoptedIPAddress(ip) {
    state.selectedAdoptedIP = ip;
    state.selectedAdoptedTab = ADOPTED_TAB_INFO;
    state.pendingClearAdoptedActivity = '';
    state.pendingDeleteAdoption = '';
    state.adoptedOverrideBindingsError = '';
    state.adoptedUpdateError = '';
    state.adoptedDetailsError = '';
    state.pingError = '';
    state.pingResult = null;
    state.pingForm = {...DEFAULT_PING_FORM};
    state.adoptedDetails = null;
    populateAdoptedOverrideBindings(null);
    populateAdoptedEditForm(getSelectedAdoptedIPAddress());
    state.view = VIEW_ADOPTED_IP;
    render();
    ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', loadStoredAdoptionConfigurations, {render: false});
    ensureLoaded('storedOverridesLoaded', 'storedOverridesLoading', loadStoredPacketOverrides, {render: false});
    await loadAdoptedIPAddressDetails(ip);
}

function updateDraftField(target) {
    if (target.dataset.adoptField) {
        state.adoptForm[target.dataset.adoptField] = target.value;
    } else if (target.dataset.adoptedEditField) {
        state.adoptedEditForm[target.dataset.adoptedEditField] = target.value;
    } else if (target.dataset.pingField) {
        state.pingForm[target.dataset.pingField] = target.value;
        state.pingError = '';
    } else if ('overrideName' in target.dataset) {
        state.overrideEditor.name = target.value;
        state.storedOverridesError = '';
        state.storedOverrideNotice = '';
    } else if (target.dataset.overrideControl === 'value') {
        state.overrideEditor.layers[target.dataset.overrideLayer][target.dataset.overrideField].value = target.value;
        state.storedOverridesError = '';
        state.storedOverrideNotice = '';
    } else if (target.dataset.adoptedOverrideField) {
        state.adoptedOverrideBindingsForm[target.dataset.adoptedOverrideField] = target.value;
        state.adoptedOverrideBindingsError = '';
    } else if (target.dataset.storedConfigField) {
        state.storedConfigEditor[target.dataset.storedConfigField] = target.value;
        state.storedConfigsError = '';
        state.storedConfigNotice = '';
    }
}

async function handleClick(event) {
    const target = event.target.closest('button');

    if (target) {
        if (target.dataset.openModule) {
            openModule(target.dataset.openModule);
            return;
        }
        if ('openAdoptForm' in target.dataset) {
            openAdoptForm();
            return;
        }
        if (target.dataset.adoptedTab) {
            state.selectedAdoptedTab = target.dataset.adoptedTab;
            state.pendingClearAdoptedActivity = '';
            render();
            return;
        }
        if (target.dataset.adoptMode) {
            state.adoptMode = target.dataset.adoptMode;
            state.adoptError = '';
            render();
            if (state.adoptMode === ADOPT_MODE_STORED) {
                ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', loadStoredAdoptionConfigurations);
            }
            return;
        }
        if (target.dataset.adoptStoredConfig) {
            await submitStoredAdoption(target.dataset.adoptStoredConfig);
            return;
        }
        if ('newStoredConfig' in target.dataset) {
            state.selectedStoredConfigLabel = '';
            state.pendingDeleteStoredConfig = '';
            state.storedConfigNotice = '';
            state.storedConfigsError = '';
            state.storedConfigEditor = createStoredConfigEditor();
            syncStoredConfigEditorInterface();
            render();
            return;
        }
        if (target.dataset.editStoredConfig) {
            const selectedConfig = findByField(state.storedConfigs, 'label', target.dataset.editStoredConfig);
            if (selectedConfig) {
                state.selectedStoredConfigLabel = selectedConfig.label;
                state.pendingDeleteStoredConfig = '';
                state.storedConfigNotice = '';
                state.storedConfigsError = '';
                state.storedConfigEditor = createStoredConfigEditor(selectedConfig);
                render();
            }
            return;
        }
        if (target.dataset.stageDeleteStoredConfig) {
            state.pendingDeleteStoredConfig = target.dataset.stageDeleteStoredConfig;
            render();
            return;
        }
        if (target.dataset.confirmDeleteStoredConfig) {
            await deleteStoredAdoptionConfiguration(target.dataset.confirmDeleteStoredConfig);
            return;
        }
        if ('newStoredOverride' in target.dataset) {
            state.selectedStoredOverrideName = '';
            state.pendingDeleteStoredOverride = '';
            state.storedOverrideNotice = '';
            state.storedOverridesError = '';
            state.overrideEditor = createPacketOverrideEditor();
            render();
            return;
        }
        if (target.dataset.editStoredOverride) {
            const selectedOverride = findByField(state.storedOverrides, 'name', target.dataset.editStoredOverride);
            if (selectedOverride) {
                state.selectedStoredOverrideName = selectedOverride.name;
                state.pendingDeleteStoredOverride = '';
                state.storedOverrideNotice = '';
                state.storedOverridesError = '';
                state.overrideEditor = createPacketOverrideEditor(selectedOverride);
                render();
            }
            return;
        }
        if (target.dataset.stageDeleteStoredOverride) {
            state.pendingDeleteStoredOverride = target.dataset.stageDeleteStoredOverride;
            render();
            return;
        }
        if (target.dataset.confirmDeleteStoredOverride) {
            await deleteStoredPacketOverride(target.dataset.confirmDeleteStoredOverride);
            return;
        }
        if ('refreshAdoptedDetails' in target.dataset) {
            if (state.selectedAdoptedIP) {
                await loadAdoptedIPAddressDetails(state.selectedAdoptedIP);
            }
            return;
        }
        if (target.dataset.stageClearAdoptedActivity) {
            state.pendingClearAdoptedActivity = target.dataset.stageClearAdoptedActivity;
            render();
            return;
        }
        if (target.dataset.stageDeleteAdoption) {
            state.pendingDeleteAdoption = target.dataset.stageDeleteAdoption;
            render();
            return;
        }
        if (target.dataset.confirmClearAdoptedActivity) {
            await clearAdoptedActivity(target.dataset.confirmClearAdoptedActivity);
            return;
        }
        if (target.dataset.confirmDeleteAdoption) {
            await deleteAdoption(target.dataset.confirmDeleteAdoption);
            return;
        }
        if ('cancelClearAdoptedActivity' in target.dataset) {
            state.pendingClearAdoptedActivity = '';
            render();
            return;
        }
        if ('cancelDeleteAdoption' in target.dataset) {
            state.pendingDeleteAdoption = '';
            render();
            return;
        }
        if ('cancelDeleteStoredConfig' in target.dataset) {
            state.pendingDeleteStoredConfig = '';
            render();
            return;
        }
        if ('cancelDeleteStoredOverride' in target.dataset) {
            state.pendingDeleteStoredOverride = '';
            render();
            return;
        }
        if ('goHome' in target.dataset) {
            state.view = VIEW_HOME;
            state.adoptError = '';
            state.adoptedUpdateError = '';
            state.adoptedDetailsError = '';
            state.storedConfigNotice = '';
            state.storedOverrideNotice = '';
            state.adoptedOverrideBindingsError = '';
            state.pingError = '';
            state.pingResult = null;
            state.pendingClearAdoptedActivity = '';
            state.pendingDeleteAdoption = '';
            state.pendingDeleteStoredConfig = '';
            state.pendingDeleteStoredOverride = '';
            render();
            return;
        }
        if (target.dataset.interface) {
            state.selectedName = target.dataset.interface;
            render();
            return;
        }
        if ('resetAdoptedEdit' in target.dataset) {
            populateAdoptedEditForm(getSelectedAdoptedIPAddress());
            state.adoptedUpdateError = '';
            render();
            return;
        }
        if (target.id === 'refresh-interfaces') {
            loadInterfaces({preserveSelection: true});
            return;
        }

        return;
    }

    const card = event.target.closest('[data-open-adopted-ip]');
    if (card?.dataset.openAdoptedIp) {
        await openAdoptedIPAddress(card.dataset.openAdoptedIp);
    }
}

async function handleKeydown(event) {
    if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) {
        return;
    }
    if (event.key !== 'Enter' && event.key !== ' ') {
        return;
    }
    if (event.target.closest('button, input, select, textarea')) {
        return;
    }

    const card = event.target.closest('[data-open-adopted-ip]');
    if (!card?.dataset.openAdoptedIp) {
        return;
    }

    event.preventDefault();
    await openAdoptedIPAddress(card.dataset.openAdoptedIp);
}

function handleInput(event) {
    const target = event.target;
    if (target.id === 'interface-search') {
        state.query = target.value;
        render({preserveSearch: true});
        return;
    }

    updateDraftField(target);
}

function handleChange(event) {
    const target = event.target;

    if (target.dataset.overrideControl === 'toggle') {
        const section = PACKET_OVERRIDE_SCHEMA.find((item) => item.layer === target.dataset.overrideLayer);
        const field = section?.fields.find((item) => item.name === target.dataset.overrideField);
        const draft = state.overrideEditor.layers[target.dataset.overrideLayer][target.dataset.overrideField];

        draft.enabled = target.checked;
        draft.value = target.checked ? (draft.value || defaultOverrideFieldValue(field || {})) : '';
        state.storedOverridesError = '';
        state.storedOverrideNotice = '';
        render();
        return;
    }

    updateDraftField(target);
}

async function handleSubmit(event) {
    const form = event.target;

    if (form.id === 'adopt-ip-form') {
        event.preventDefault();
        await submitAdoption(new FormData(form));
        return;
    }

    if (form.id === 'adopted-ip-edit-form') {
        event.preventDefault();
        await submitAdoptionUpdate(new FormData(form));
        return;
    }

    if (form.id === 'adopted-ip-ping-form') {
        event.preventDefault();
        await submitAdoptedIPAddressPing(new FormData(form));
        return;
    }

    if (form.id === 'stored-packet-override-form') {
        event.preventDefault();
        await submitStoredPacketOverride();
        return;
    }

    if (form.id === 'stored-adoption-config-form') {
        event.preventDefault();
        await submitStoredAdoptionConfigurationDraft();
        return;
    }

    if (form.id === 'adopted-arp-override-form' || form.id === 'adopted-icmp-override-form') {
        event.preventDefault();
        await submitAdoptedOverrideBindings();
    }
}

function attachEventDelegates() {
    root.addEventListener('click', handleClick);
    root.addEventListener('keydown', handleKeydown);
    root.addEventListener('input', handleInput);
    root.addEventListener('change', handleChange);
    root.addEventListener('submit', handleSubmit);
}

function render(options = {}) {
    switch (state.view) {
    case MODULE_LOCAL_NETWORK: {
        const items = filteredInterfaces();
        const selected = getSelectedInterface(items);
        if (selected) {
            state.selectedName = selected.name;
        }
        root.innerHTML = renderLocalNetworkModule({items, selected, state});
        break;
    }
    case MODULE_PACKET_OVERRIDES:
        root.innerHTML = renderPacketOverridesModule({schema: PACKET_OVERRIDE_SCHEMA, state});
        break;
    case MODULE_STORED_ADOPTIONS:
        root.innerHTML = renderStoredAdoptionsModule({
            interfaces: adoptableInterfaces(state.storedConfigEditor.interfaceName),
            state,
        });
        break;
    case VIEW_ADOPT_FORM:
        root.innerHTML = renderAdoptIPAddressForm({interfaces: adoptableInterfaces(), state});
        break;
    case VIEW_ADOPTED_IP:
        root.innerHTML = renderAdoptedIPAddressView({
            interfaces: adoptableInterfaces(state.adoptedEditForm.interfaceName || getSelectedAdoptedIPAddress()?.interfaceName || ''),
            details: getSelectedAdoptedIPAddressDetails(),
            item: getSelectedAdoptedIPAddress(),
            state,
        });
        break;
    default:
        root.innerHTML = renderModuleHome({
            logo,
            moduleLocalNetwork: MODULE_LOCAL_NETWORK,
            modulePacketOverrides: MODULE_PACKET_OVERRIDES,
            moduleStoredAdoptions: MODULE_STORED_ADOPTIONS,
            state,
        });
        break;
    }

    const searchInput = document.getElementById('interface-search');
    if (searchInput) {
        searchInput.value = state.query;
    }

    if (options.preserveSearch && state.view === MODULE_LOCAL_NETWORK) {
        searchInput?.focus();
        searchInput?.setSelectionRange(state.query.length, state.query.length);
    }
}

async function loadInterfaces(options = {}) {
    state.interfacesLoading = true;
    state.interfaceError = '';

    if (options.render !== false) {
        render();
    }

    try {
        const snapshot = await ListInterfaces();
        state.snapshot = snapshot;

        if (!options.preserveSelection || !snapshot.interfaces.some((item) => item.name === state.selectedName)) {
            state.selectedName = snapshot.interfaces[0]?.name || '';
        }

        syncAdoptionFormInterface();
        syncStoredConfigEditorInterface();
    } catch (error) {
        state.interfaceError = error?.message || String(error);
    } finally {
        state.interfacesLoading = false;

        if (options.render !== false) {
            render();
        }
    }
}

async function loadAdoptedIPAddresses(options = {}) {
    state.adoptionsError = '';

    try {
        setAdoptedItems(await ListAdoptedIPAddresses());
    } catch (error) {
        state.adoptionsError = error?.message || String(error);
    } finally {
        if (options.render !== false) {
            render();
        }
    }
}

async function loadStoredAdoptionConfigurations(options = {}) {
    await loadStoredItems(
        options,
        {loadingKey: 'storedConfigsLoading', errorKey: 'storedConfigsError', loadedKey: 'storedConfigsLoaded'},
        ListStoredAdoptionConfigurations,
        setStoredConfigs,
    );
}

async function loadStoredPacketOverrides(options = {}) {
    await loadStoredItems(
        options,
        {loadingKey: 'storedOverridesLoading', errorKey: 'storedOverridesError', loadedKey: 'storedOverridesLoaded'},
        ListStoredPacketOverrides,
        setStoredOverrides,
    );
}

async function loadAdoptedIPAddressDetails(ip, options = {}) {
    if (!ip) {
        state.adoptedDetails = null;
        state.adoptedDetailsError = '';
        state.adoptedDetailsLoading = false;
        populateAdoptedOverrideBindings(null);
        if (options.render !== false) {
            render();
        }
        return;
    }

    state.adoptedDetailsLoading = true;
    state.adoptedDetailsError = '';

    if (state.adoptedDetails?.ip !== ip) {
        state.adoptedDetails = null;
    }

    if (options.render !== false) {
        render();
    }

    try {
        const details = await GetAdoptedIPAddressDetails(ip);
        if (state.selectedAdoptedIP !== ip) {
            return;
        }
        state.adoptedDetails = details;
        populateAdoptedOverrideBindings(details);
    } catch (error) {
        if (state.selectedAdoptedIP !== ip) {
            return;
        }
        state.adoptedDetailsError = error?.message || String(error);
    } finally {
        if (state.selectedAdoptedIP !== ip) {
            return;
        }
        state.adoptedDetailsLoading = false;

        if (options.render !== false) {
            render();
        }
    }
}

async function submitAdoption(formData) {
    state.adopting = true;
    state.adoptError = '';
    state.adoptForm.label = String(formData.get('label') || '').trim();
    state.adoptForm.interfaceName = String(formData.get('interfaceName') || '').trim();
    state.adoptForm.ip = String(formData.get('ip') || '').trim();
    state.adoptForm.defaultGateway = String(formData.get('defaultGateway') || '').trim();
    state.adoptForm.mac = String(formData.get('mac') || '').trim();
    render();

    try {
        const result = await AdoptIPAddress({
            label: state.adoptForm.label,
            interfaceName: state.adoptForm.interfaceName,
            ip: state.adoptForm.ip,
            defaultGateway: state.adoptForm.defaultGateway,
            mac: state.adoptForm.mac,
        });

        upsertAdoptedItem(result);
        state.selectedAdoptedIP = result.ip;
        state.adoptForm.label = '';
        state.adoptForm.ip = '';
        state.adoptForm.defaultGateway = '';
        state.adoptForm.mac = '';
        syncAdoptionFormInterface();
        state.view = VIEW_HOME;
    } catch (error) {
        state.adoptError = error?.message || String(error);
    } finally {
        state.adopting = false;
        render();
    }
}

async function submitStoredAdoption(label) {
    if (!label || state.adoptingStoredLabel || state.deletingStoredConfigLabel) {
        return;
    }

    state.adoptingStoredLabel = label;
    state.adoptError = '';
    render();

    try {
        const result = await AdoptStoredAdoptionConfiguration(label);
        upsertAdoptedItem(result);
        state.selectedAdoptedIP = result.ip;
        state.view = VIEW_HOME;
    } catch (error) {
        state.adoptError = error?.message || String(error);
    } finally {
        state.adoptingStoredLabel = '';
        render();
    }
}

async function deleteStoredAdoptionConfiguration(label) {
    await deleteStoredItem(
        label,
        {
            busyKey: 'deletingStoredConfigLabel',
            pendingKey: 'pendingDeleteStoredConfig',
            errorKey: 'storedConfigsError',
            noticeKey: 'storedConfigNotice',
        },
        DeleteStoredAdoptionConfiguration,
        (value) => setStoredConfigs(removeByField(state.storedConfigs, 'label', value)),
    );
}

async function submitStoredPacketOverride() {
    if (state.savingStoredOverride) {
        return;
    }

    state.savingStoredOverride = true;
    state.storedOverridesError = '';
    state.storedOverrideNotice = '';
    render();

    try {
        const payload = buildStoredPacketOverridePayload(state.overrideEditor);
        const saved = await SaveStoredPacketOverride(payload);
        state.selectedStoredOverrideName = saved.name;
        state.overrideEditor = createPacketOverrideEditor(saved);
        setStoredOverrides(upsertByField(state.storedOverrides, 'name', saved));
        state.storedOverridesLoaded = true;
        state.storedOverrideNotice = `Stored packet override "${saved.name}".`;
    } catch (error) {
        state.storedOverridesError = error?.message || String(error);
    } finally {
        state.savingStoredOverride = false;
        render();
    }
}

async function deleteStoredPacketOverride(name) {
    await deleteStoredItem(
        name,
        {
            busyKey: 'deletingStoredOverrideName',
            pendingKey: 'pendingDeleteStoredOverride',
            errorKey: 'storedOverridesError',
            noticeKey: 'storedOverrideNotice',
        },
        DeleteStoredPacketOverride,
        (value) => setStoredOverrides(removeByField(state.storedOverrides, 'name', value)),
    );
}

async function submitStoredAdoptionConfigurationDraft() {
    if (state.savingStoredConfig) {
        return;
    }

    state.savingStoredConfig = true;
    state.storedConfigsError = '';
    state.storedConfigNotice = '';
    render();

    try {
        const payload = {
            label: String(state.storedConfigEditor.label || '').trim(),
            interfaceName: String(state.storedConfigEditor.interfaceName || '').trim(),
            ip: String(state.storedConfigEditor.ip || '').trim(),
            defaultGateway: String(state.storedConfigEditor.defaultGateway || '').trim(),
            mac: String(state.storedConfigEditor.mac || '').trim(),
        };

        if (!payload.label) {
            throw new Error('Label is required.');
        }

        const saved = await SaveStoredAdoptionConfiguration(payload);
        state.selectedStoredConfigLabel = saved.label;
        state.storedConfigEditor = createStoredConfigEditor(saved);
        setStoredConfigs(upsertByField(state.storedConfigs, 'label', saved));
        state.storedConfigsLoaded = true;
        state.storedConfigNotice = `Stored configuration "${saved.label}".`;
    } catch (error) {
        state.storedConfigsError = error?.message || String(error);
    } finally {
        state.savingStoredConfig = false;
        render();
    }
}

async function submitAdoptionUpdate(formData) {
    state.updatingAdoption = true;
    state.adoptedUpdateError = '';
    state.pingError = '';
    state.pingResult = null;
    state.adoptedEditForm.label = String(formData.get('label') || '').trim();
    state.adoptedEditForm.interfaceName = String(formData.get('interfaceName') || '').trim();
    state.adoptedEditForm.ip = String(formData.get('ip') || '').trim();
    state.adoptedEditForm.defaultGateway = String(formData.get('defaultGateway') || '').trim();
    state.adoptedEditForm.mac = String(formData.get('mac') || '').trim();
    render();

    try {
        const result = await UpdateAdoptedIPAddress({
            label: state.adoptedEditForm.label,
            currentIP: state.adoptedEditForm.currentIP,
            interfaceName: state.adoptedEditForm.interfaceName,
            ip: state.adoptedEditForm.ip,
            defaultGateway: state.adoptedEditForm.defaultGateway,
            mac: state.adoptedEditForm.mac,
        });

        upsertAdoptedItem(result, state.adoptedEditForm.currentIP);
        state.selectedAdoptedIP = result.ip;
        populateAdoptedEditForm(result);
        await loadAdoptedIPAddressDetails(result.ip, {render: false});
    } catch (error) {
        state.adoptedUpdateError = error?.message || String(error);
    } finally {
        state.updatingAdoption = false;
        render();
    }
}

async function submitAdoptedIPAddressPing(formData) {
    if (!state.selectedAdoptedIP || state.pingingAdoptedIP) {
        return;
    }

    const targetIP = String(formData.get('targetIP') || '').trim();
    const countText = String(formData.get('count') || '').trim();
    let count = 0;

    if (countText !== '') {
        count = Number.parseInt(countText, 10);
        if (!Number.isInteger(count) || count <= 0) {
            state.pingError = 'Ping count must be a positive integer.';
            render();
            return;
        }
    }

    state.pingingAdoptedIP = true;
    state.pingError = '';
    state.pingResult = null;
    state.pingForm.targetIP = targetIP;
    state.pingForm.count = countText;
    render();

    try {
        const result = await PingAdoptedIPAddress({
            sourceIP: state.selectedAdoptedIP,
            targetIP,
            count,
        });
        state.pingResult = result;
        await loadAdoptedIPAddressDetails(state.selectedAdoptedIP, {render: false});
    } catch (error) {
        state.pingError = error?.message || String(error);
    } finally {
        state.pingingAdoptedIP = false;
        render();
    }
}

async function submitAdoptedOverrideBindings() {
    if (!state.selectedAdoptedIP || state.savingAdoptedOverrideBindings) {
        return;
    }

    state.savingAdoptedOverrideBindings = true;
    state.adoptedOverrideBindingsError = '';
    render();

    try {
        const details = await UpdateAdoptedIPAddressOverrideBindings({
            ip: state.selectedAdoptedIP,
            bindings: state.adoptedOverrideBindingsForm,
        });

        state.adoptedDetails = details;
        populateAdoptedOverrideBindings(details);
    } catch (error) {
        state.adoptedOverrideBindingsError = error?.message || String(error);
    } finally {
        state.savingAdoptedOverrideBindings = false;
        render();
    }
}

async function deleteAdoption(ip) {
    if (!ip || state.deletingAdoption) {
        return;
    }

    state.deletingAdoption = true;
    state.pendingDeleteAdoption = '';
    state.adoptionsError = '';
    state.adoptedUpdateError = '';
    render();

    try {
        await ReleaseIPAddress(ip);
        removeAdoptedItem(ip);
        state.selectedAdoptedIP = '';
        state.selectedAdoptedTab = ADOPTED_TAB_INFO;
        state.pendingClearAdoptedActivity = '';
        state.pendingDeleteAdoption = '';
        state.adoptedDetails = null;
        state.adoptedDetailsError = '';
        state.adoptedOverrideBindingsError = '';
        state.pingError = '';
        state.pingResult = null;
        populateAdoptedEditForm(null);
        populateAdoptedOverrideBindings(null);
        state.view = VIEW_HOME;
    } catch (error) {
        state.adoptionsError = error?.message || String(error);
    } finally {
        state.deletingAdoption = false;
        render();
    }
}

async function clearAdoptedActivity(scope) {
    if (!state.selectedAdoptedIP || state.clearingAdoptedActivity) {
        return;
    }

    state.clearingAdoptedActivity = true;
    state.pendingClearAdoptedActivity = '';
    state.adoptedDetailsError = '';
    render();

    try {
        await ClearAdoptedIPAddressActivity(state.selectedAdoptedIP, scope);
        await loadAdoptedIPAddressDetails(state.selectedAdoptedIP, {render: false});
    } catch (error) {
        state.adoptedDetailsError = error?.message || String(error);
    } finally {
        state.clearingAdoptedActivity = false;
        render();
    }
}

async function initialize() {
    attachEventDelegates();
    render();
    await Promise.all([
        loadInterfaces({render: false}),
        loadAdoptedIPAddresses({render: false}),
    ]);
    render();
}

initialize();
