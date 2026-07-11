import {createScriptEditor, SCRIPT_KIND_GENERIC, SCRIPT_KIND_TRANSPORT} from '../scriptModel';
import * as Backend from '../../wailsjs/go/main/App';
import {
    activeScriptState,
    clearSelectedAdoptedIPAddress,
    findServiceDefinition,
    createStoredConfigEditor,
    populateAdoptedServiceForms,
    populateAdoptedScriptName,
    removeAdoptedItem,
    removeByField,
    SERVICE_DEFINITIONS,
    setAdoptedItems,
    setServiceDefinitions,
    setStoredConfigs,
    setGenericScripts,
    setStoredScripts,
    state,
    syncAdoptFormInterfaceName,
    syncStoredConfigInterfaceName,
    upsertStoredScriptItem,
    upsertAdoptedItem,
    upsertByField,
    VIEW_HOME,
} from './state';

const APP_BACKEND_METHODS = new Set(['ChooseDirectory', 'CreateKeytab', 'GetConfigurationDirectory', 'ListAdoptionInterfaces']);

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
        return Boolean(state.selectedServiceSourceIP) && !state.startingAdoptedService && !state.stoppingAdoptedService;
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

    const loadGenericScripts = createStoredLoader(
        {loadingKey: 'genericScriptsLoading', errorKey: 'genericScriptsError', loadedKey: 'genericScriptsLoaded'},
        () => backendCall('ListStoredGenericScripts'),
        setGenericScripts,
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
            const selectedKey = options.selectedKey || 'selectedAdoptedIP';
            if (state[selectedKey] !== ip) {
                return;
            }
            setAdoptedDetails(details);
        } catch (error) {
            const selectedKey = options.selectedKey || 'selectedAdoptedIP';
            if (state[selectedKey] !== ip) {
                return;
            }
            state.adoptedDetailsError = messageFromError(error);
        } finally {
            const selectedKey = options.selectedKey || 'selectedAdoptedIP';
            if (state[selectedKey] !== ip) {
                return;
            }
            state.adoptedDetailsLoading = false;
            renderIfNeeded(options);
        }
    }

    async function loadStoredScriptDocument(key, options = {}) {
        const scriptState = activeScriptState();
        if (!key) {
            state[scriptState.selectedKey] = '';
            state.scriptEditor = createScriptEditor(null, scriptState.kind);
            renderIfNeeded(options);
            return;
        }

        state[scriptState.errorKey] = '';
        renderIfNeeded(options);

        try {
            const method = scriptState.kind === SCRIPT_KIND_GENERIC ? 'GetStoredGenericScript' : 'GetStoredScript';
            const script = await backendCall(method, key);
            state[scriptState.selectedKey] = script.name;
            state.scriptEditor = createScriptEditor(script, scriptState.kind);
        } catch (error) {
            state[scriptState.errorKey] = messageFromError(error);
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

    async function submitStoredScript() {
        const scriptState = activeScriptState();
        await saveStoredItem(
            {
                busyKey: 'savingStoredScript',
                errorKey: scriptState.errorKey,
                noticeKey: scriptState.noticeKey,
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
            (value) => backendCall(scriptState.kind === SCRIPT_KIND_GENERIC ? 'SaveStoredGenericScript' : 'SaveStoredScript', value),
            (saved) => {
                state[scriptState.selectedKey] = saved.name;
                state.scriptEditor = createScriptEditor(saved, scriptState.kind);
                if (scriptState.kind === SCRIPT_KIND_GENERIC) {
                    setGenericScripts(state.genericScriptsLoaded ? upsertStoredScriptItem(state.genericScripts, saved) : [saved]);
                    state.genericScriptsLoaded = true;
                } else {
                    setStoredScripts(state.storedScriptsLoaded ? upsertStoredScriptItem(state.storedScripts, saved) : [saved]);
                    state.storedScriptsLoaded = true;
                }
                state[scriptState.noticeKey] = saved.available
                    ? `Stored script "${saved.name}".`
                    : `Stored script "${saved.name}" with a compile issue.`;
            },
        );
    }

    async function refreshStoredScriptsInventory() {
        const scriptState = activeScriptState();
        state[scriptState.loadingKey] = true;
        state[scriptState.errorKey] = '';
        state[scriptState.noticeKey] = '';
        render();

        try {
            const isGeneric = scriptState.kind === SCRIPT_KIND_GENERIC;
            const items = await backendCall(isGeneric ? 'RefreshStoredGenericScripts' : 'RefreshStoredScripts');
            (isGeneric ? setGenericScripts : setStoredScripts)(items);
            state[scriptState.loadedKey] = true;
            if (state[scriptState.selectedKey]) {
                const selected = await backendCall(isGeneric ? 'GetStoredGenericScript' : 'GetStoredScript', state[scriptState.selectedKey]);
                state.scriptEditor = createScriptEditor(selected, scriptState.kind);
            }
            state[scriptState.noticeKey] = 'Script library refreshed from disk.';
        } catch (error) {
            state[scriptState.errorKey] = messageFromError(error);
        } finally {
            state[scriptState.loadingKey] = false;
            render();
        }
    }

    async function deleteStoredScript(key) {
        const scriptState = activeScriptState();
        await deleteStoredItem(
            key,
            {
                busyKey: scriptState.deletingKey,
                pendingKey: scriptState.pendingDeleteKey,
                errorKey: scriptState.errorKey,
                noticeKey: scriptState.noticeKey,
            },
            (value) => backendCall(scriptState.kind === SCRIPT_KIND_GENERIC ? 'DeleteStoredGenericScript' : 'DeleteStoredScript', value),
            (removed) => {
                if (scriptState.kind === SCRIPT_KIND_GENERIC) {
                    setGenericScripts(removeByField(state.genericScripts, 'name', removed));
                } else {
                    setStoredScripts(removeByField(state.storedScripts, 'name', removed));
                }
                state[scriptState.loadedKey] = true;
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
        (value) => backendCall('SaveStoredAdoptionConfiguration', state.selectedStoredConfigLabel, value),
        (saved) => {
            const previousLabel = state.selectedStoredConfigLabel;
            state.selectedStoredConfigLabel = saved.label;
            state.storedConfigEditor = createStoredConfigEditor(saved);
            setStoredConfigs(upsertByField(removeByField(state.storedConfigs, 'label', previousLabel), 'label', saved));
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
        if (!state.selectedOperationSourceIP || state.resolvingAdoptedDNS) {
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
                sourceIP: state.selectedOperationSourceIP,
                server,
                name,
                type,
                transport,
                timeoutMillis,
            });
            state.dnsResult = result;
            await loadAdoptedIPAddressDetails(state.selectedOperationSourceIP, {render: false, selectedKey: 'selectedOperationSourceIP'});
        } catch (error) {
            state.dnsError = messageFromError(error);
        } finally {
            state.resolvingAdoptedDNS = false;
            render();
        }
    }

    async function submitAdoptedIPAddressPing(formData) {
        if (!state.selectedOperationSourceIP || state.pinging) {
            return;
        }

        const destination = String(formData.get('destination') || '').trim();
        const intervalText = String(formData.get('intervalMillis') || '').trim();
        const timeoutText = String(formData.get('timeoutMillis') || '').trim();
        const countText = String(formData.get('count') || '').trim();
        const payloadText = String(formData.get('payloadSize') || '').trim();
        const intervalMillis = Number.parseInt(intervalText, 10);
        const timeoutMillis = Number.parseInt(timeoutText, 10);
        const count = Number.parseInt(countText, 10);
        const payloadSize = Number.parseInt(payloadText, 10);
        if (!Number.isInteger(intervalMillis) || intervalMillis <= 0
            || !Number.isInteger(timeoutMillis) || timeoutMillis <= 0
            || !Number.isInteger(count) || count <= 0
            || !Number.isInteger(payloadSize) || payloadSize < 0) {
            state.pingError = 'Interval, timeout, and count must be positive integers; payload may be zero.';
            render();
            return;
        }

        state.pinging = true;
        state.pingError = '';
        state.pingResult = null;
        state.pingForm.destination = destination;
        state.pingForm.intervalMillis = intervalText;
        state.pingForm.timeoutMillis = timeoutText;
        state.pingForm.count = countText;
        state.pingForm.payloadSize = payloadText;
        render();

        try {
            state.pingResult = await backendCall('PingAdoptedIPAddress', {
                sourceIP: state.selectedOperationSourceIP,
                destination,
                intervalMillis,
                timeoutMillis,
                count,
                payloadSize,
            });
        } catch (error) {
            state.pingError = messageFromError(error);
        } finally {
            state.pinging = false;
            render();
        }
    }

    async function stopAdoptedIPAddressPing() {
        if (!state.pinging) {
            return;
        }
        try {
            await backendCall('StopPingAdoptedIPAddress');
        } catch (error) {
            state.pingError = messageFromError(error);
            render();
        }
    }

    async function createKeytab(formData) {
        if (state.creatingKeytab) {
            return;
        }
        const kvno = Number.parseInt(String(formData.get('kvno') || ''), 10);
        if (!Number.isInteger(kvno) || kvno < 0 || kvno > 255) {
            state.keytabError = 'KVNO must be between 0 and 255.';
            render();
            return;
        }
        state.creatingKeytab = true;
        state.keytabError = '';
        state.keytabResult = null;
        try {
            const result = await backendCall('CreateKeytab', {
                principal: String(formData.get('principal') || '').trim(),
                realm: String(formData.get('realm') || '').trim(),
                password: String(formData.get('password') || ''),
                kvno,
                fileName: String(formData.get('fileName') || '').trim(),
                encryptionTypes: [...state.keytabForm.encryptionTypes],
            });
            state.keytabResult = result;
            state.keytabForm.password = '';
        } catch (error) {
            state.keytabError = messageFromError(error);
        } finally {
            state.creatingKeytab = false;
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
                'UpdateAdoptedIPAddressScript',
                state.selectedAdoptedIP,
                state.adoptedTransportScriptName,
            );

            setAdoptedDetails(details);
        } catch (error) {
            state.adoptedScriptError = messageFromError(error);
        } finally {
            state.savingAdoptedScript = false;
            render();
        }
    }

    async function runGenericScript() {
        if (!state.selectedGenericRunScriptName || state.runningGenericScript) {
            return;
        }
        state.runningGenericScript = true;
        state.genericScriptRunError = '';
        state.genericScriptRunResult = null;
        render();

        try {
            state.genericScriptRunResult = await backendCall('RunStoredGenericScript', {
                scriptName: state.selectedGenericRunScriptName,
            });
        } catch (error) {
            state.genericScriptRunError = messageFromError(error);
        } finally {
            state.runningGenericScript = false;
            render();
        }
    }

    async function stopGenericScript() {
        if (!state.runningGenericScript) {
            return;
        }
        try {
            await backendCall('StopStoredGenericScript');
        } catch (error) {
            state.genericScriptRunError = messageFromError(error);
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
            () => backendCall('StartAdoptedIPAddressService', state.selectedServiceSourceIP, serviceName, config),
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
            () => backendCall('StopAdoptedIPAddressService', state.selectedServiceSourceIP, serviceName),
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
        loadGenericScripts,
        loadStoredScripts,
        refreshStoredScriptsInventory,
        startAdoptedIPAddressRecording,
        startAdoptedService,
        stopAdoptedIPAddressRecording,
        stopAdoptedService,
        stopAdoptedIPAddressPing,
        chooseServiceDirectoryField,
        createKeytab,
        submitAdoptedIPAddressDNS,
        submitAdoptedIPAddressPing,
        submitAdoptedScript,
        runGenericScript,
        stopGenericScript,
        submitAdoption,
        submitAdoptedMTU,
        submitStoredAdoption,
        submitStoredAdoptionConfigurationDraft,
        submitStoredScript,
    };
}
