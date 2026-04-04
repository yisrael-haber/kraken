import './style.css';
import './app.css';

import logo from './assets/images/kraken_logo.png';
import {renderAdoptIPAddressForm, renderAdoptedIPAddressView} from './ui/adoption';
import {renderModuleHome} from './ui/home';
import {renderLocalNetworkModule} from './ui/localNetwork';
import {
    AdoptIPAddress,
    AdoptStoredAdoptionConfiguration,
    ClearAdoptedIPAddressActivity,
    GetAdoptedIPAddressDetails,
    ListAdoptedIPAddresses,
    ListInterfaces,
    ListStoredAdoptionConfigurations,
    ReleaseIPAddress,
    SaveStoredAdoptionConfiguration,
    UpdateAdoptedIPAddress,
} from '../wailsjs/go/main/App';

const VIEW_HOME = 'home';
const VIEW_ADOPT_FORM = 'adopt-form';
const VIEW_ADOPTED_IP = 'adopted-ip';
const MODULE_LOCAL_NETWORK = 'local-network';
const ADOPT_MODE_RAW = 'raw';
const ADOPT_MODE_STORED = 'stored';
const ADOPTED_TAB_INFO = 'info';
const ADOPTED_TAB_ARP = 'arp';
const ADOPTED_TAB_ICMP = 'icmp';

const state = {
    view: VIEW_HOME,
    snapshot: null,
    adoptedItems: [],
    adoptedDetails: null,
    storedConfigs: [],
    selectedName: '',
    selectedAdoptedIP: '',
    adoptMode: ADOPT_MODE_RAW,
    selectedAdoptedTab: ADOPTED_TAB_INFO,
    query: '',
    interfacesLoading: false,
    adoptedDetailsLoading: false,
    storedConfigsLoading: false,
    interfaceError: '',
    adoptionsError: '',
    adoptedDetailsError: '',
    storedConfigsError: '',
    adopting: false,
    adoptingStoredLabel: '',
    updatingAdoption: false,
    deletingAdoption: false,
    clearingAdoptedActivity: false,
    storingAdoptionConfig: false,
    pendingClearAdoptedActivity: '',
    pendingDeleteAdoption: '',
    adoptError: '',
    adoptedUpdateError: '',
    adoptionConfigError: '',
    adoptionConfigNotice: '',
    adoptForm: {
        label: '',
        interfaceName: '',
        ip: '',
        mac: '',
    },
    adoptedEditForm: {
        label: '',
        currentIP: '',
        interfaceName: '',
        ip: '',
        mac: '',
    },
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

function hasStoredConfigurationLabel(label) {
    const normalized = String(label || '').trim();
    return normalized !== '' && state.storedConfigs.some((item) => item.label === normalized);
}

function populateAdoptedEditForm(item) {
    if (!item) {
        state.adoptedEditForm = {
            label: '',
            currentIP: '',
            interfaceName: '',
            ip: '',
            mac: '',
        };
        return;
    }

    state.adoptedEditForm = {
        label: item.label,
        currentIP: item.ip,
        interfaceName: item.interfaceName,
        ip: item.ip,
        mac: item.mac,
    };
}

function openModule(moduleName) {
    state.view = moduleName;

    if (moduleName === MODULE_LOCAL_NETWORK && !state.snapshot && !state.interfacesLoading) {
        loadInterfaces();
        return;
    }

    render();
}

function openAdoptForm() {
    state.view = VIEW_ADOPT_FORM;
    state.adoptMode = ADOPT_MODE_RAW;
    state.adoptError = '';
    state.storedConfigsError = '';
    syncAdoptionFormInterface();
    render();

    if (!state.snapshot && !state.interfacesLoading) {
        loadInterfaces();
    }
}

async function openAdoptedIPAddress(ip) {
    state.selectedAdoptedIP = ip;
    state.selectedAdoptedTab = ADOPTED_TAB_INFO;
    state.pendingClearAdoptedActivity = '';
    state.pendingDeleteAdoption = '';
    state.adoptedUpdateError = '';
    state.adoptedDetailsError = '';
    state.adoptionConfigError = '';
    state.adoptionConfigNotice = '';
    state.adoptedDetails = null;
    populateAdoptedEditForm(getSelectedAdoptedIPAddress());
    state.view = VIEW_ADOPTED_IP;
    render();
    if (!state.storedConfigs.length && !state.storedConfigsLoading) {
        loadStoredAdoptionConfigurations({render: false});
    }
    await loadAdoptedIPAddressDetails(ip);
}

function updateDraftField(target) {
    if (target.dataset.adoptField) {
        state.adoptForm[target.dataset.adoptField] = target.value;
    } else if (target.dataset.adoptedEditField) {
        state.adoptedEditForm[target.dataset.adoptedEditField] = target.value;
        state.adoptionConfigError = '';
        state.adoptionConfigNotice = '';
    }
}

async function handleClick(event) {
    const target = event.target.closest('button');
    if (!target) {
        return;
    }

    if (target.dataset.openModule) {
        openModule(target.dataset.openModule);
        return;
    }
    if ('openAdoptForm' in target.dataset) {
        openAdoptForm();
        return;
    }
    if (target.dataset.openAdoptedIp) {
        await openAdoptedIPAddress(target.dataset.openAdoptedIp);
        return;
    }
    if (target.dataset.adoptedTab) {
        state.selectedAdoptedTab = target.dataset.adoptedTab;
        state.pendingClearAdoptedActivity = '';
        render();
        if (state.selectedAdoptedIP) {
            await loadAdoptedIPAddressDetails(state.selectedAdoptedIP);
        }
        return;
    }
    if (target.dataset.adoptMode) {
        state.adoptMode = target.dataset.adoptMode;
        state.adoptError = '';
        render();
        if (state.adoptMode === ADOPT_MODE_STORED && !state.storedConfigs.length && !state.storedConfigsLoading) {
            await loadStoredAdoptionConfigurations();
        }
        return;
    }
    if (target.dataset.adoptStoredConfig) {
        await submitStoredAdoption(target.dataset.adoptStoredConfig);
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
    if ('goHome' in target.dataset) {
        state.view = VIEW_HOME;
        state.adoptError = '';
        state.adoptedUpdateError = '';
        state.adoptedDetailsError = '';
        state.adoptionConfigError = '';
        state.adoptionConfigNotice = '';
        state.pendingClearAdoptedActivity = '';
        state.pendingDeleteAdoption = '';
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
    if ('storeAdoptionConfig' in target.dataset) {
        await saveCurrentAdoptionConfiguration();
        return;
    }
    if (target.id === 'refresh-interfaces') {
        loadInterfaces({preserveSelection: true});
    }
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
    updateDraftField(event.target);
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
    }
}

function attachEventDelegates() {
    root.addEventListener('click', handleClick);
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
        root.innerHTML = renderLocalNetworkModule({items, logo, selected, state});
        break;
    }
    case VIEW_ADOPT_FORM:
        root.innerHTML = renderAdoptIPAddressForm({interfaces: adoptableInterfaces(), state});
        break;
    case VIEW_ADOPTED_IP:
        root.innerHTML = renderAdoptedIPAddressView({
            interfaces: adoptableInterfaces(state.adoptedEditForm.interfaceName || getSelectedAdoptedIPAddress()?.interfaceName || ''),
            details: getSelectedAdoptedIPAddressDetails(),
            hasStoredConfig: hasStoredConfigurationLabel(state.adoptedEditForm.label),
            item: getSelectedAdoptedIPAddress(),
            state,
        });
        break;
    default:
        root.innerHTML = renderModuleHome({logo, moduleLocalNetwork: MODULE_LOCAL_NETWORK, state});
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
        const items = await ListAdoptedIPAddresses();
        state.adoptedItems = items;

        if (!items.some((item) => item.ip === state.selectedAdoptedIP)) {
            state.selectedAdoptedIP = items[0]?.ip || '';
        }
    } catch (error) {
        state.adoptionsError = error?.message || String(error);
    } finally {
        if (options.render !== false) {
            render();
        }
    }
}

async function loadStoredAdoptionConfigurations(options = {}) {
    state.storedConfigsLoading = true;
    state.storedConfigsError = '';

    if (options.render !== false) {
        render();
    }

    try {
        state.storedConfigs = await ListStoredAdoptionConfigurations();
    } catch (error) {
        state.storedConfigsError = error?.message || String(error);
    } finally {
        state.storedConfigsLoading = false;

        if (options.render !== false) {
            render();
        }
    }
}

async function loadAdoptedIPAddressDetails(ip, options = {}) {
    if (!ip) {
        state.adoptedDetails = null;
        state.adoptedDetailsError = '';
        state.adoptedDetailsLoading = false;
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
    state.adoptForm.mac = String(formData.get('mac') || '').trim();
    render();

    try {
        const result = await AdoptIPAddress({
            label: state.adoptForm.label,
            interfaceName: state.adoptForm.interfaceName,
            ip: state.adoptForm.ip,
            mac: state.adoptForm.mac,
        });

        await loadAdoptedIPAddresses({render: false});

        state.selectedAdoptedIP = result.ip;
        state.adoptForm.label = '';
        state.adoptForm.ip = '';
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
    if (!label || state.adoptingStoredLabel) {
        return;
    }

    state.adoptingStoredLabel = label;
    state.adoptError = '';
    render();

    try {
        const result = await AdoptStoredAdoptionConfiguration(label);
        await loadAdoptedIPAddresses({render: false});
        state.selectedAdoptedIP = result.ip;
        state.view = VIEW_HOME;
    } catch (error) {
        state.adoptError = error?.message || String(error);
    } finally {
        state.adoptingStoredLabel = '';
        render();
    }
}

async function submitAdoptionUpdate(formData) {
    state.updatingAdoption = true;
    state.adoptedUpdateError = '';
    state.adoptedEditForm.label = String(formData.get('label') || '').trim();
    state.adoptedEditForm.interfaceName = String(formData.get('interfaceName') || '').trim();
    state.adoptedEditForm.ip = String(formData.get('ip') || '').trim();
    state.adoptedEditForm.mac = String(formData.get('mac') || '').trim();
    render();

    try {
        const result = await UpdateAdoptedIPAddress({
            label: state.adoptedEditForm.label,
            currentIP: state.adoptedEditForm.currentIP,
            interfaceName: state.adoptedEditForm.interfaceName,
            ip: state.adoptedEditForm.ip,
            mac: state.adoptedEditForm.mac,
        });

        await loadAdoptedIPAddresses({render: false});

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

async function saveCurrentAdoptionConfiguration() {
    if (state.storingAdoptionConfig) {
        return;
    }

    state.storingAdoptionConfig = true;
    state.adoptionConfigError = '';
    state.adoptionConfigNotice = '';
    render();

    try {
        const saved = await SaveStoredAdoptionConfiguration({
            label: state.adoptedEditForm.label,
            interfaceName: state.adoptedEditForm.interfaceName,
            ip: state.adoptedEditForm.ip,
            mac: state.adoptedEditForm.mac,
        });
        await loadStoredAdoptionConfigurations({render: false});
        state.adoptionConfigNotice = `Stored configuration "${saved.label}".`;
    } catch (error) {
        state.adoptionConfigError = error?.message || String(error);
    } finally {
        state.storingAdoptionConfig = false;
        render();
    }
}

async function deleteAdoption(ip) {
    if (!ip || state.deletingAdoption) {
        return;
    }

    state.deletingAdoption = true;
    state.pendingDeleteAdoption = '';
    state.adoptedUpdateError = '';
    render();

    try {
        await ReleaseIPAddress(ip);
        await loadAdoptedIPAddresses({render: false});
        state.selectedAdoptedIP = '';
        state.selectedAdoptedTab = ADOPTED_TAB_INFO;
        state.pendingClearAdoptedActivity = '';
        state.pendingDeleteAdoption = '';
        state.adoptedDetails = null;
        state.adoptedDetailsError = '';
        populateAdoptedEditForm(null);
        state.view = VIEW_HOME;
    } catch (error) {
        state.adoptedUpdateError = error?.message || String(error);
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
