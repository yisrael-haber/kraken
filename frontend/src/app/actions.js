import {buildStoredPacketOverridePayload, createPacketOverrideEditor} from '../packetOverrideModel';
import {createScriptEditor} from '../scriptModel';
import {
    AdoptIPAddress,
    AdoptStoredAdoptionConfiguration,
    ClearAdoptedIPAddressActivity,
    DeleteStoredAdoptionConfiguration,
    DeleteStoredPacketOverride,
    DeleteStoredScript,
    GetAdoptedIPAddressDetails,
    GetConfigurationDirectory,
    GetStoredScript,
    ListAdoptedIPAddresses,
    ListInterfaces,
    ListStoredAdoptionConfigurations,
    ListStoredPacketOverrides,
    ListStoredScripts,
    PingAdoptedIPAddress,
    RefreshStoredScripts,
    ReleaseIPAddress,
    SaveStoredAdoptionConfiguration,
    SaveStoredPacketOverride,
    SaveStoredScript,
    UpdateAdoptedIPAddressOverrideBindings,
    UpdateAdoptedIPAddress,
} from '../../wailsjs/go/main/App';
import {
    ADOPTED_TAB_INFO,
    createStoredConfigEditor,
    DEFAULT_PING_FORM,
    populateAdoptedEditForm,
    populateAdoptedOverrideBindings,
    removeAdoptedItem,
    removeByField,
    setAdoptedItems,
    setStoredConfigs,
    setStoredOverrides,
    setStoredScripts,
    state,
    syncAdoptionFormInterface,
    syncStoredConfigEditorInterface,
    upsertAdoptedItem,
    upsertByField,
    VIEW_HOME,
} from './state';

export function createActions(render) {
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

    async function loadConfigurationDirectory(options = {}) {
        state.configurationDirectoryLoading = true;
        state.configurationDirectoryError = '';

        if (options.render !== false) {
            render();
        }

        try {
            state.configurationDirectory = await GetConfigurationDirectory();
        } catch (error) {
            state.configurationDirectoryError = error?.message || String(error);
        } finally {
            state.configurationDirectoryLoading = false;

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

    async function loadStoredScripts(options = {}) {
        await loadStoredItems(
            options,
            {loadingKey: 'storedScriptsLoading', errorKey: 'storedScriptsError', loadedKey: 'storedScriptsLoaded'},
            ListStoredScripts,
            setStoredScripts,
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

    async function loadStoredScriptDocument(name, options = {}) {
        if (!name) {
            state.selectedStoredScriptName = '';
            state.scriptEditor = createScriptEditor();
            if (options.render !== false) {
                render();
            }
            return;
        }

        state.storedScriptsError = '';
        if (options.render !== false) {
            render();
        }

        try {
            const script = await GetStoredScript(name);
            state.selectedStoredScriptName = script.name;
            state.scriptEditor = createScriptEditor(script);
        } catch (error) {
            state.storedScriptsError = error?.message || String(error);
        } finally {
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

    async function submitStoredScript() {
        if (state.savingStoredScript) {
            return;
        }

        state.savingStoredScript = true;
        state.storedScriptsError = '';
        state.storedScriptNotice = '';
        render();

        try {
            const payload = {
                name: String(state.scriptEditor.name || '').trim(),
                source: String(state.scriptEditor.source || ''),
            };

            if (!payload.name) {
                throw new Error('Name is required.');
            }

            const saved = await SaveStoredScript(payload);
            state.selectedStoredScriptName = saved.name;
            state.scriptEditor = createScriptEditor(saved);
            setStoredScripts(upsertByField(state.storedScripts, 'name', saved));
            state.storedScriptsLoaded = true;
            state.storedScriptNotice = saved.available
                ? `Stored script "${saved.name}".`
                : `Stored script "${saved.name}" with a compile issue.`;
        } catch (error) {
            state.storedScriptsError = error?.message || String(error);
        } finally {
            state.savingStoredScript = false;
            render();
        }
    }

    async function refreshStoredScriptsInventory() {
        state.storedScriptsLoading = true;
        state.storedScriptsError = '';
        state.storedScriptNotice = '';
        render();

        try {
            const items = await RefreshStoredScripts();
            setStoredScripts(items);
            state.storedScriptsLoaded = true;
            if (state.selectedStoredScriptName) {
                const selected = await GetStoredScript(state.selectedStoredScriptName);
                state.scriptEditor = createScriptEditor(selected);
            }
            state.storedScriptNotice = 'Script inventory refreshed from disk.';
        } catch (error) {
            state.storedScriptsError = error?.message || String(error);
        } finally {
            state.storedScriptsLoading = false;
            render();
        }
    }

    async function deleteStoredScript(name) {
        await deleteStoredItem(
            name,
            {
                busyKey: 'deletingStoredScriptName',
                pendingKey: 'pendingDeleteStoredScript',
                errorKey: 'storedScriptsError',
                noticeKey: 'storedScriptNotice',
            },
            DeleteStoredScript,
            (value) => setStoredScripts(removeByField(state.storedScripts, 'name', value)),
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
            state.pingForm = {...DEFAULT_PING_FORM};
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

    return {
        clearAdoptedActivity,
        deleteAdoption,
        deleteStoredAdoptionConfiguration,
        deleteStoredPacketOverride,
        deleteStoredScript,
        loadAdoptedIPAddressDetails,
        loadAdoptedIPAddresses,
        loadConfigurationDirectory,
        loadInterfaces,
        loadStoredScriptDocument,
        loadStoredAdoptionConfigurations,
        loadStoredPacketOverrides,
        loadStoredScripts,
        refreshStoredScriptsInventory,
        submitAdoptedIPAddressPing,
        submitAdoptedOverrideBindings,
        submitAdoption,
        submitAdoptionUpdate,
        submitStoredAdoption,
        submitStoredAdoptionConfigurationDraft,
        submitStoredPacketOverride,
        submitStoredScript,
    };
}
