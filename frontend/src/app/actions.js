import {createScriptEditor} from '../scriptModel';
import * as Backend from '../../wailsjs/go/main/App';
import {
    clearSelectedAdoptedIPAddress,
    findServiceDefinition,
    createStoredConfigEditor,
    parseStoredScriptKey,
    populateAdoptedServiceForms,
    populateAdoptedScriptName,
    removeAdoptedItem,
    removeByField,
    SERVICE_DEFINITIONS,
    setAdoptedItems,
    setServiceDefinitions,
    setStoredConfigs,
    setStoredScripts,
    state,
    storedScriptKey,
    syncAdoptFormInterfaceName,
    syncStoredConfigInterfaceName,
    upsertStoredScriptItem,
    upsertAdoptedItem,
    upsertByField,
    VIEW_HOME,
} from './state';

const APP_BACKEND_METHODS = new Set(['ChooseDirectory', 'GetConfigurationDirectory', 'ListAdoptionInterfaces']);

async function backendCall(name, ...args) {
	await Backend.ResetSignalHandlers();
	if (APP_BACKEND_METHODS.has(name)) {
		return Backend[name](...args);
	}
	return window['go']['adoption']['Manager'][name](...args);
}

export function createActions(render) {
    const IDENTITY_FORM_FIELDS = ['label', 'interfaceName', 'ip', 'subnetPrefix', 'defaultGateway', 'mtu', 'mac'];

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
        populateAdoptedServiceForms();
    }

    function clearAdoptedRecordingFeedback() {
        state.adoptedRecordingError = '';
        state.adoptedRecordingNotice = '';
    }

    function clearAdoptedServiceFeedback() {
        state.adoptedServiceError = '';
        state.adoptedServiceNotice = '';
    }

    function canChangeAdoptedRecording() {
        return Boolean(state.selectedAdoptedIP) && !state.startingAdoptedRecording && !state.stoppingAdoptedRecording;
    }

    function canChangeAdoptedService() {
        return Boolean(state.selectedAdoptedIP) && !state.startingAdoptedService && !state.stoppingAdoptedService;
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

    async function runAdoptedServiceAction(busyKey, serviceName, request, noticeForDetails) {
        if (!canChangeAdoptedService()) {
            return;
        }

        state[busyKey] = serviceName;
        clearAdoptedServiceFeedback();
        render();

        try {
            const details = await request();
            setAdoptedDetails(details);
            state.adoptedServiceNotice = noticeForDetails(details);
        } catch (error) {
            state.adoptedServiceError = messageFromError(error);
        } finally {
            state[busyKey] = '';
            render();
        }
    }

    function parseTCPServicePort(text, label) {
        const value = String(text || '').trim();
        const parsed = Number.parseInt(value, 10);

        if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
            throw new Error(`${label} port must be between 1 and 65535.`);
        }

        return parsed;
    }

    function parseIdentityMTU(text) {
        const value = String(text || '').trim();
        if (!value) {
            return 0;
        }

        const parsed = Number.parseInt(value, 10);
        if (!Number.isInteger(parsed) || parsed < 68 || parsed > 65535) {
            throw new Error('MTU must be between 68 and 65535.');
        }

        return parsed;
    }

    function parseSubnetPrefix(text) {
        const value = String(text || '').trim();
        if (!value) {
            return 0;
        }

        const parsed = Number.parseInt(value, 10);
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > 32) {
            throw new Error('Prefix must be between 1 and 32.');
        }

        return parsed;
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
            state.interfaceSelection = await backendCall('ListAdoptionInterfaces');

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
            state.configurationDirectory = await backendCall('GetConfigurationDirectory');
        } catch (error) {
            state.configurationDirectoryError = messageFromError(error);
        } finally {
            renderIfNeeded(options);
        }
    }

    async function loadServiceDefinitions(options = {}) {
        state.serviceDefinitionsError = '';
        state.serviceDefinitionsLoading = false;
        setServiceDefinitions(SERVICE_DEFINITIONS);
        state.serviceDefinitionsLoaded = true;
        renderIfNeeded(options);
    }

    async function loadAdoptedIPAddresses(options = {}) {
        state.adoptionsError = '';

        try {
            setAdoptedItems(await backendCall('ListAdoptedIPAddresses'));
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
        () => backendCall('ListStoredAdoptionConfigurations'),
        setStoredConfigs,
    );

    const loadStoredScripts = createStoredLoader(
        {loadingKey: 'storedScriptsLoading', errorKey: 'storedScriptsError', loadedKey: 'storedScriptsLoaded'},
        () => backendCall('ListStoredScripts'),
        setStoredScripts,
    );

    async function loadAdoptedIPAddressDetails(ip, options = {}) {
        if (!ip) {
            state.adoptedDetails = null;
            state.adoptedDetailsError = '';
            state.adoptedDetailsLoading = false;
            populateAdoptedScriptName(null);
            populateAdoptedServiceForms();
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
            const details = await backendCall('GetAdoptedIPAddressDetails', ip);
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

    async function loadStoredScriptDocument(key, options = {}) {
        if (!key) {
            state.selectedStoredScriptKey = '';
            state.scriptEditor = createScriptEditor(null, state.selectedStoredScriptSurface);
            renderIfNeeded(options);
            return;
        }

        state.storedScriptsError = '';
        renderIfNeeded(options);

        try {
            const script = await backendCall('GetStoredScript', parseStoredScriptKey(key));
            state.selectedStoredScriptKey = storedScriptKey(script);
            state.selectedStoredScriptSurface = script.surface;
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
            const result = await backendCall('AdoptIPAddress', {
                label: state.adoptForm.label,
                interfaceName: state.adoptForm.interfaceName,
                ip: state.adoptForm.ip,
                subnetPrefix: parseSubnetPrefix(state.adoptForm.subnetPrefix),
                defaultGateway: state.adoptForm.defaultGateway,
                mtu: parseIdentityMTU(state.adoptForm.mtu),
                mac: state.adoptForm.mac,
            });

            upsertAdoptedItem(result);
            state.selectedAdoptedIP = result.ip;
            state.adoptForm.label = '';
            state.adoptForm.ip = '';
            state.adoptForm.subnetPrefix = '24';
            state.adoptForm.defaultGateway = '';
            state.adoptForm.mtu = '';
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
            const result = await backendCall('AdoptStoredAdoptionConfiguration', label);
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
        (value) => backendCall('DeleteStoredAdoptionConfiguration', value),
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
                surface: String(state.scriptEditor.surface || '').trim(),
                source: String(state.scriptEditor.source || ''),
            };

            if (!payload.name) {
                throw new Error('Name is required.');
            }

            return payload;
        },
        (value) => backendCall('SaveStoredScript', value),
        (saved) => {
            state.selectedStoredScriptKey = storedScriptKey(saved);
            state.selectedStoredScriptSurface = saved.surface;
            state.scriptEditor = createScriptEditor(saved);
            setStoredScripts(state.storedScriptsLoaded ? upsertStoredScriptItem(state.storedScripts, saved) : [saved]);
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
            const items = await backendCall('RefreshStoredScripts');
            setStoredScripts(items);
            state.storedScriptsLoaded = true;
            if (state.selectedStoredScriptKey) {
                const selected = await backendCall('GetStoredScript', parseStoredScriptKey(state.selectedStoredScriptKey));
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

    async function deleteStoredScript(key) {
        await deleteStoredItem(
            key,
            {
                busyKey: 'deletingStoredScriptName',
                pendingKey: 'pendingDeleteStoredScript',
                errorKey: 'storedScriptsError',
                noticeKey: 'storedScriptNotice',
            },
            (value) => backendCall('DeleteStoredScript', parseStoredScriptKey(value)),
            (removed) => {
                setStoredScripts(removeByField(state.storedScripts, 'key', removed));
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
                subnetPrefix: parseSubnetPrefix(state.storedConfigEditor.subnetPrefix),
                defaultGateway: String(state.storedConfigEditor.defaultGateway || '').trim(),
                mtu: parseIdentityMTU(state.storedConfigEditor.mtu),
                mac: String(state.storedConfigEditor.mac || '').trim(),
            };

            if (!payload.label) {
                throw new Error('Label is required.');
            }

            return payload;
        },
        (value) => backendCall('SaveStoredAdoptionConfiguration', value),
        (saved) => {
            state.selectedStoredConfigLabel = saved.label;
            state.storedConfigEditor = createStoredConfigEditor(saved);
            setStoredConfigs(upsertByField(state.storedConfigs, 'label', saved));
            state.storedConfigsLoaded = true;
            state.storedConfigNotice = `Stored configuration "${saved.label}".`;
        },
    );

    async function submitAdoptedMTU(formData) {
        state.updatingAdoptedMTU = true;
        state.adoptedMTUError = '';
        state.dnsError = '';
        state.dnsResult = null;
        const mtu = String(formData.get('mtu') || '').trim();
        render();

        try {
            const result = await backendCall('UpdateAdoptedIPAddressMTU', state.selectedAdoptedIP, parseIdentityMTU(mtu));

            upsertAdoptedItem(result);
            state.selectedAdoptedIP = result.ip;
            await loadAdoptedIPAddressDetails(result.ip, {render: false});
        } catch (error) {
            state.adoptedMTUError = messageFromError(error);
        } finally {
            state.updatingAdoptedMTU = false;
            render();
        }
    }

    async function submitAdoptedIPAddressDNS(formData) {
        if (!state.selectedAdoptedIP || state.resolvingAdoptedDNS) {
            return;
        }

        const server = String(formData.get('server') || '').trim();
        const name = String(formData.get('name') || '').trim();
        const type = String(formData.get('type') || '').trim();
        const transport = String(formData.get('transport') || '').trim();
        const timeoutText = String(formData.get('timeoutMillis') || '').trim();
        let timeoutMillis = 0;

        if (timeoutText !== '') {
            timeoutMillis = Number.parseInt(timeoutText, 10);
            if (!Number.isInteger(timeoutMillis) || timeoutMillis <= 0) {
                state.dnsError = 'Timeout must be a positive integer in milliseconds.';
                render();
                return;
            }
        }

        state.resolvingAdoptedDNS = true;
        state.dnsError = '';
        state.dnsResult = null;
        state.dnsForm.server = server;
        state.dnsForm.name = name;
        state.dnsForm.type = type;
        state.dnsForm.transport = transport;
        state.dnsForm.timeoutMillis = timeoutText;
        render();

        try {
            const result = await backendCall('ResolveDNSAdoptedIPAddress', {
                sourceIP: state.selectedAdoptedIP,
                server,
                name,
                type,
                transport,
                timeoutMillis,
            });
            state.dnsResult = result;
            await loadAdoptedIPAddressDetails(state.selectedAdoptedIP, {render: false});
        } catch (error) {
            state.dnsError = messageFromError(error);
        } finally {
            state.resolvingAdoptedDNS = false;
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
            const details = await backendCall(
                'UpdateAdoptedIPAddressScripts',
                state.selectedAdoptedIP,
                state.adoptedTransportScriptName,
                state.adoptedApplicationScriptName,
            );

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
            () => backendCall('StartAdoptedIPAddressRecording', state.selectedAdoptedIP, outputPath),
            (details) => details.recording?.outputPath
                ? `Recording to ${details.recording.outputPath}.`
                : 'Recording started.',
        );
    }

    async function stopAdoptedIPAddressRecording() {
        await runAdoptedRecordingAction(
            'stoppingAdoptedRecording',
            () => backendCall('StopAdoptedIPAddressRecording', state.selectedAdoptedIP),
            () => 'Recording stopped.',
        );
    }

    async function startAdoptedService(serviceName) {
        if (!canChangeAdoptedService()) {
            return;
        }

        const definition = findServiceDefinition(state.serviceDefinitions, serviceName);
        if (!definition) {
            state.adoptedServiceError = `Unknown service "${serviceName}".`;
            render();
            return;
        }

        const currentForm = state.adoptedServiceForms[serviceName] || {};
        const config = {};
        for (const field of definition.fields || []) {
            let value = String(currentForm[field.name] || '').trim();
            if (field.type === 'port') {
                try {
                    value = String(parseTCPServicePort(value, definition.label || serviceName));
                } catch (error) {
                    state.adoptedServiceError = messageFromError(error);
                    render();
                    return;
                }
            }
            if (field.required && !value) {
                state.adoptedServiceError = `${field.label} is required.`;
                render();
                return;
            }
            config[field.name] = value;
        }

        await runAdoptedServiceAction(
            'startingAdoptedService',
            serviceName,
            () => backendCall('StartAdoptedIPAddressService', state.selectedAdoptedIP, serviceName, config),
            (details) => {
                const status = (details.services || []).find((item) => item.service === serviceName);
                return status?.port
                    ? `${definition.label} on ${status.port}.`
                    : `${definition.label} started.`;
            },
        );
        render();
    }

    async function stopAdoptedService(serviceName) {
        const definition = findServiceDefinition(state.serviceDefinitions, serviceName);
        await runAdoptedServiceAction(
            'stoppingAdoptedService',
            serviceName,
            () => backendCall('StopAdoptedIPAddressService', state.selectedAdoptedIP, serviceName),
            () => `${definition?.label || serviceName} stopped and port freed.`,
        );
    }

    async function chooseServiceDirectoryField(serviceName, fieldName) {
        clearAdoptedServiceFeedback();
        render();

        try {
            const currentForm = state.adoptedServiceForms[serviceName] || {};
            const selected = await backendCall('ChooseDirectory', String(currentForm[fieldName] || ''));
            if (!selected) {
                return;
            }

            if (!state.adoptedServiceForms[serviceName]) {
                state.adoptedServiceForms[serviceName] = {};
            }
            state.adoptedServiceForms[serviceName][fieldName] = selected;
            render();
        } catch (error) {
            state.adoptedServiceError = messageFromError(error);
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
        state.adoptedMTUError = '';
        render();

        try {
            await backendCall('ReleaseIPAddress', ip);
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

    return {
        deleteAdoption,
        deleteStoredAdoptionConfiguration,
        deleteStoredScript,
        loadAdoptedIPAddressDetails,
        loadAdoptedIPAddresses,
        loadConfigurationDirectory,
        loadInterfaceSelection,
        loadServiceDefinitions,
        loadStoredScriptDocument,
        loadStoredAdoptionConfigurations,
        loadStoredScripts,
        refreshStoredScriptsInventory,
        startAdoptedIPAddressRecording,
        startAdoptedService,
        stopAdoptedIPAddressRecording,
        stopAdoptedService,
        chooseServiceDirectoryField,
        submitAdoptedIPAddressDNS,
        submitAdoptedScript,
        submitAdoption,
        submitAdoptedMTU,
        submitStoredAdoption,
        submitStoredAdoptionConfigurationDraft,
        submitStoredScript,
    };
}
