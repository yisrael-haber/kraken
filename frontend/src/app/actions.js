import {createScriptEditor} from '../scriptModel';
import {
    AdoptIPAddress,
    AdoptStoredAdoptionConfiguration,
    ChooseAdoptedIPAddressRecordingPath,
    ClearAdoptedIPAddressActivity,
    DeleteStoredAdoptionConfiguration,
    DeleteStoredScript,
    GetAdoptedIPAddressDetails,
    GetConfigurationDirectory,
    GetStoredScript,
    ListAdoptionInterfaces,
    ListAdoptedIPAddresses,
    ListStoredAdoptionConfigurations,
    ListStoredScripts,
    PingAdoptedIPAddress,
    RefreshStoredScripts,
    ReleaseIPAddress,
    SaveStoredAdoptionConfiguration,
    SaveStoredScript,
    StartAdoptedIPAddressRecording,
    StopAdoptedIPAddressRecording,
    UpdateAdoptedIPAddressScript,
    UpdateAdoptedIPAddress,
} from '../../wailsjs/go/main/App';
import {
    clearSelectedAdoptedIPAddress,
    createStoredConfigEditor,
    populateAdoptedEditForm,
    populateAdoptedScriptName,
    removeAdoptedItem,
    removeByField,
    setAdoptedItems,
    setStoredConfigs,
    setStoredScripts,
    state,
    syncAdoptFormInterfaceName,
    syncStoredConfigInterfaceName,
    upsertAdoptedItem,
    upsertByField,
    VIEW_HOME,
} from './state';

export function createActions(render) {
    const IDENTITY_FORM_FIELDS = ['label', 'interfaceName', 'ip', 'defaultGateway', 'mac'];

    function messageFromError(error) {
        return error?.message || String(error);
    }

    function renderIfNeeded(options = {}) {
        if (options.render !== false) {
            render();
        }
    }

    function setAdoptedDetails(details) {
        state.adoptedDetails = details;
        populateAdoptedScriptName(details);
    }

    function clearAdoptedRecordingFeedback() {
        state.adoptedRecordingError = '';
        state.adoptedRecordingNotice = '';
    }

    function canChangeAdoptedRecording() {
        return Boolean(state.selectedAdoptedIP) && !state.startingAdoptedRecording && !state.stoppingAdoptedRecording;
    }

    async function runAdoptedRecordingAction(busyKey, request, noticeForDetails) {
        if (!canChangeAdoptedRecording()) {
            return;
        }

        state[busyKey] = true;
        clearAdoptedRecordingFeedback();
        render();

        try {
            const details = await request();
            setAdoptedDetails(details);
            state.adoptedRecordingNotice = noticeForDetails(details);
        } catch (error) {
            state.adoptedRecordingError = messageFromError(error);
        } finally {
            state[busyKey] = false;
            render();
        }
    }

    function syncTrimmedFields(target, formData, fields) {
        for (const field of fields) {
            target[field] = String(formData.get(field) || '').trim();
        }
    }

    async function loadStoredItems(options, {loadingKey, errorKey, loadedKey}, loader, setter) {
        if (state[loadingKey]) {
            return;
        }

        state[loadingKey] = true;
        state[errorKey] = '';
        renderIfNeeded(options);

        try {
            setter(await loader());
            state[loadedKey] = true;
        } catch (error) {
            state[errorKey] = messageFromError(error);
        } finally {
            state[loadingKey] = false;
            renderIfNeeded(options);
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
            state[errorKey] = messageFromError(error);
        } finally {
            state[busyKey] = '';
            render();
        }
    }

    async function saveStoredItem({busyKey, errorKey, noticeKey}, buildPayload, request, onSuccess) {
        if (state[busyKey]) {
            return;
        }

        state[busyKey] = true;
        state[errorKey] = '';
        state[noticeKey] = '';
        render();

        try {
            const saved = await request(buildPayload());
            onSuccess(saved);
        } catch (error) {
            state[errorKey] = messageFromError(error);
        } finally {
            state[busyKey] = false;
            render();
        }
    }

    async function loadInterfaceSelection(options = {}) {
        state.interfaceSelectionLoading = true;
        state.interfaceSelectionError = '';
        renderIfNeeded(options);

        try {
            state.interfaceSelection = await ListAdoptionInterfaces();

            syncAdoptFormInterfaceName();
            syncStoredConfigInterfaceName();
        } catch (error) {
            state.interfaceSelectionError = messageFromError(error);
        } finally {
            state.interfaceSelectionLoading = false;
            renderIfNeeded(options);
        }
    }

    async function loadConfigurationDirectory(options = {}) {
        state.configurationDirectoryError = '';
        renderIfNeeded(options);

        try {
            state.configurationDirectory = await GetConfigurationDirectory();
        } catch (error) {
            state.configurationDirectoryError = messageFromError(error);
        } finally {
            renderIfNeeded(options);
        }
    }

    async function loadAdoptedIPAddresses(options = {}) {
        state.adoptionsError = '';

        try {
            setAdoptedItems(await ListAdoptedIPAddresses());
        } catch (error) {
            state.adoptionsError = messageFromError(error);
        } finally {
            renderIfNeeded(options);
        }
    }

    const createStoredLoader = (keys, loader, setter) => (options = {}) =>
        loadStoredItems(options, keys, loader, setter);

    const loadStoredAdoptionConfigurations = createStoredLoader(
        {loadingKey: 'storedConfigsLoading', errorKey: 'storedConfigsError', loadedKey: 'storedConfigsLoaded'},
        ListStoredAdoptionConfigurations,
        setStoredConfigs,
    );

    const loadStoredScripts = createStoredLoader(
        {loadingKey: 'storedScriptsLoading', errorKey: 'storedScriptsError', loadedKey: 'storedScriptsLoaded'},
        ListStoredScripts,
        setStoredScripts,
    );

    async function loadAdoptedIPAddressDetails(ip, options = {}) {
        if (!ip) {
            state.adoptedDetails = null;
            state.adoptedDetailsError = '';
            state.adoptedDetailsLoading = false;
            populateAdoptedScriptBindings(null);
            renderIfNeeded(options);
            return;
        }

        state.adoptedDetailsLoading = true;
        state.adoptedDetailsError = '';

        if (state.adoptedDetails?.ip !== ip) {
            state.adoptedDetails = null;
        }

        renderIfNeeded(options);

        try {
            const details = await GetAdoptedIPAddressDetails(ip);
            if (state.selectedAdoptedIP !== ip) {
                return;
            }
            setAdoptedDetails(details);
        } catch (error) {
            if (state.selectedAdoptedIP !== ip) {
                return;
            }
            state.adoptedDetailsError = messageFromError(error);
        } finally {
            if (state.selectedAdoptedIP !== ip) {
                return;
            }
            state.adoptedDetailsLoading = false;
            renderIfNeeded(options);
        }
    }

    async function loadStoredScriptDocument(name, options = {}) {
        if (!name) {
            state.selectedStoredScriptName = '';
            state.scriptEditor = createScriptEditor();
            renderIfNeeded(options);
            return;
        }

        state.storedScriptsError = '';
        renderIfNeeded(options);

        try {
            const script = await GetStoredScript(name);
            state.selectedStoredScriptName = script.name;
            state.scriptEditor = createScriptEditor(script);
        } catch (error) {
            state.storedScriptsError = messageFromError(error);
        } finally {
            renderIfNeeded(options);
        }
    }

    async function submitAdoption(formData) {
        state.adopting = true;
        state.adoptError = '';
        syncTrimmedFields(state.adoptForm, formData, IDENTITY_FORM_FIELDS);
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
            syncAdoptFormInterfaceName();
            state.view = VIEW_HOME;
        } catch (error) {
            state.adoptError = messageFromError(error);
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
            state.adoptError = messageFromError(error);
        } finally {
            state.adoptingStoredLabel = '';
            render();
        }
    }

    const createStoredDeleter = (itemsKey, field, keys, request, setter) => (value) =>
        deleteStoredItem(value, keys, request, (removed) => setter(removeByField(state[itemsKey], field, removed)));

    const createStoredSaver = (keys, buildPayload, request, onSuccess) => () =>
        saveStoredItem(keys, buildPayload, request, onSuccess);

    const deleteStoredAdoptionConfiguration = createStoredDeleter(
        'storedConfigs',
        'label',
        {
            busyKey: 'deletingStoredConfigLabel',
            pendingKey: 'pendingDeleteStoredConfig',
            errorKey: 'storedConfigsError',
            noticeKey: 'storedConfigNotice',
        },
        DeleteStoredAdoptionConfiguration,
        setStoredConfigs,
    );

    const submitStoredScript = createStoredSaver(
        {
            busyKey: 'savingStoredScript',
            errorKey: 'storedScriptsError',
            noticeKey: 'storedScriptNotice',
        },
        () => {
            const payload = {
                name: String(state.scriptEditor.name || '').trim(),
                source: String(state.scriptEditor.source || ''),
            };

            if (!payload.name) {
                throw new Error('Name is required.');
            }

            return payload;
        },
        SaveStoredScript,
        (saved) => {
            state.selectedStoredScriptName = saved.name;
            state.scriptEditor = createScriptEditor(saved);
            setStoredScripts(state.storedScriptsLoaded ? upsertByField(state.storedScripts, 'name', saved) : [saved]);
            state.storedScriptsLoaded = true;
            state.storedScriptNotice = saved.available
                ? `Stored script "${saved.name}".`
                : `Stored script "${saved.name}" with a compile issue.`;
        },
    );

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
            state.storedScriptNotice = 'Script library refreshed from disk.';
        } catch (error) {
            state.storedScriptsError = messageFromError(error);
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
            (removed) => {
                setStoredScripts(removeByField(state.storedScripts, 'name', removed));
                state.storedScriptsLoaded = true;
            },
        );
    }

    const submitStoredAdoptionConfigurationDraft = createStoredSaver(
        {
            busyKey: 'savingStoredConfig',
            errorKey: 'storedConfigsError',
            noticeKey: 'storedConfigNotice',
        },
        () => {
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

            return payload;
        },
        SaveStoredAdoptionConfiguration,
        (saved) => {
            state.selectedStoredConfigLabel = saved.label;
            state.storedConfigEditor = createStoredConfigEditor(saved);
            setStoredConfigs(upsertByField(state.storedConfigs, 'label', saved));
            state.storedConfigsLoaded = true;
            state.storedConfigNotice = `Stored configuration "${saved.label}".`;
        },
    );

    async function submitAdoptionUpdate(formData) {
        state.updatingAdoption = true;
        state.adoptedUpdateError = '';
        state.pingError = '';
        state.pingResult = null;
        syncTrimmedFields(state.adoptedEditForm, formData, IDENTITY_FORM_FIELDS);
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
            state.adoptedUpdateError = messageFromError(error);
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
        const payloadHex = String(formData.get('payloadHex') || '').trim();
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
        state.pingForm.payloadHex = payloadHex;
        render();

        try {
            const result = await PingAdoptedIPAddress({
                sourceIP: state.selectedAdoptedIP,
                targetIP,
                count,
                payloadHex,
            });
            state.pingResult = result;
            await loadAdoptedIPAddressDetails(state.selectedAdoptedIP, {render: false});
        } catch (error) {
            state.pingError = messageFromError(error);
        } finally {
            state.pingingAdoptedIP = false;
            render();
        }
    }

    async function submitAdoptedScript() {
        if (!state.selectedAdoptedIP || state.savingAdoptedScript) {
            return;
        }

        state.savingAdoptedScript = true;
        state.adoptedScriptError = '';
        render();

        try {
            const details = await UpdateAdoptedIPAddressScript({
                ip: state.selectedAdoptedIP,
                scriptName: state.adoptedScriptName,
            });

            setAdoptedDetails(details);
        } catch (error) {
            state.adoptedScriptError = messageFromError(error);
        } finally {
            state.savingAdoptedScript = false;
            render();
        }
    }

    async function startAdoptedIPAddressRecording(outputPath = '') {
        await runAdoptedRecordingAction(
            'startingAdoptedRecording',
            () => StartAdoptedIPAddressRecording({
                ip: state.selectedAdoptedIP,
                outputPath,
            }),
            (details) => details.recording?.outputPath
                ? `Recording to ${details.recording.outputPath}.`
                : 'Recording started.',
        );
    }

    async function startAdoptedIPAddressRecordingWithDialog() {
        if (!canChangeAdoptedRecording()) {
            return;
        }

        clearAdoptedRecordingFeedback();
        render();

        try {
            const outputPath = await ChooseAdoptedIPAddressRecordingPath(state.selectedAdoptedIP);
            if (!outputPath) {
                return;
            }

            await startAdoptedIPAddressRecording(outputPath);
        } catch (error) {
            state.adoptedRecordingError = messageFromError(error);
            render();
        }
    }

    async function stopAdoptedIPAddressRecording() {
        await runAdoptedRecordingAction(
            'stoppingAdoptedRecording',
            () => StopAdoptedIPAddressRecording(state.selectedAdoptedIP),
            () => 'Recording stopped.',
        );
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
            clearSelectedAdoptedIPAddress();
            state.view = VIEW_HOME;
        } catch (error) {
            state.adoptionsError = messageFromError(error);
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
            state.adoptedDetailsError = messageFromError(error);
        } finally {
            state.clearingAdoptedActivity = false;
            render();
        }
    }

    return {
        clearAdoptedActivity,
        deleteAdoption,
        deleteStoredAdoptionConfiguration,
        deleteStoredScript,
        loadAdoptedIPAddressDetails,
        loadAdoptedIPAddresses,
        loadConfigurationDirectory,
        loadInterfaceSelection,
        loadStoredScriptDocument,
        loadStoredAdoptionConfigurations,
        loadStoredScripts,
        refreshStoredScriptsInventory,
        startAdoptedIPAddressRecording,
        startAdoptedIPAddressRecordingWithDialog,
        stopAdoptedIPAddressRecording,
        submitAdoptedIPAddressPing,
        submitAdoptedScript,
        submitAdoption,
        submitAdoptionUpdate,
        submitStoredAdoption,
        submitStoredAdoptionConfigurationDraft,
        submitStoredScript,
    };
}
