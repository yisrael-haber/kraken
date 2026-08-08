import {syncScriptCodeEditor} from '../scriptCodeEditor';
import {createScriptEditor, SCRIPT_KIND_GENERIC, SCRIPT_KIND_TRANSPORT} from '../scriptModel';
import {EventsOn} from '../../wailsjs/runtime/runtime';
import {createActions} from './actions';
import {createRender} from './render';
import {
    appendGenericScriptOutput,
    createStoredConfigEditor,
    findByField,
    GLOBAL_SCRIPTING_TAB_EDITOR,
    GLOBAL_SCRIPTING_TAB_RUN,
    resetAdoptedInteractionState,
    resetAdoptedViewState,
    state,
    syncInterfaceName,
    MODULE_GLOBAL_SCRIPTING,
    MODULE_KEYTAB,
    MODULE_OPERATIONS,
    MODULE_SERVICES,
    MODULE_IDENTITIES,
    MODULE_TRANSPORT_SCRIPTS,
    loadScriptEditorPreferences,
    persistScriptEditorPreferences,
    VIEW_ADOPTED_IP,
} from './state';

export function startApp(root, {logo}) {
    const baseRender = createRender(root, {logo});

    function render() {
        baseRender();
        syncScriptCodeEditor(root, state);
    }

    const actions = createActions(render);
    let outputRenderScheduled = false;

    function scheduleOutputRender() {
        if (outputRenderScheduled) {
            return;
        }
        outputRenderScheduled = true;
        window.requestAnimationFrame(() => {
            outputRenderScheduled = false;
            render();
        });
    }

    function ensureLoaded(loadedKey, loadingKey, loader, options = {}) {
        if (!state[loadedKey] && !state[loadingKey]) {
            loader(options);
        }
    }

    function resetStoredConfigEditor() {
        state.selectedStoredConfigLabel = '';
        state.pendingDeleteStoredConfig = '';
        state.pendingCopyStoredConfig = '';
        state.storedConfigCopyLabel = '';
        state.storedConfigNotice = '';
        state.storedConfigsError = '';
        state.storedConfigEditor = createStoredConfigEditor();
        syncInterfaceName(state.storedConfigEditor);
        render();
    }

    function selectStoredConfigEditor(label) {
        const selected = findByField(state.storedConfigs, 'label', label);
        if (!selected) {
            return;
        }

        state.selectedStoredConfigLabel = selected.label;
        state.pendingDeleteStoredConfig = '';
        state.pendingCopyStoredConfig = '';
        state.storedConfigCopyLabel = '';
        state.storedConfigNotice = '';
        state.storedConfigsError = '';
        state.storedConfigEditor = createStoredConfigEditor(selected);
        render();
    }

    function stagePending(stateKey, value) {
        state[stateKey] = value;
        render();
    }

    function clearPending(stateKey) {
        state[stateKey] = '';
        render();
    }

    function activateScriptKind(kind) {
        state.activeScriptKind = kind;
        if (kind === SCRIPT_KIND_GENERIC) {
            state.scriptEditor = createScriptEditor(
                state.genericScripts.find((item) => item.name === state.selectedGenericScriptKey) || null,
                SCRIPT_KIND_GENERIC,
            );
            ensureLoaded('genericScriptsLoaded', 'genericScriptsLoading', actions.loadGenericScripts);
        } else {
            state.scriptEditor = createScriptEditor(
                state.storedScripts.find((item) => item.name === state.selectedStoredScriptKey) || null,
                SCRIPT_KIND_TRANSPORT,
            );
            ensureLoaded('storedScriptsLoaded', 'storedScriptsLoading', actions.loadStoredScripts);
        }
        render();
    }

    const buttonCommands = [
        ['refreshStoredScripts', actions.refreshStoredScriptsInventory],
        ['runGenericScript', actions.runGenericScript],
        ['stopGenericScript', actions.stopGenericScript],
        ['startAdoptedRecording', actions.startAdoptedIPAddressRecording],
        ['stopAdoptedRecording', actions.stopAdoptedIPAddressRecording],
    ];

    const formActions = {
        'adopted-mtu-form': (form) => actions.submitAdoptedMTU(new FormData(form)),
        'adopted-ip-dns-form': actions.submitAdoptedIPAddressDNS,
        'adopted-ip-ping-form': actions.submitAdoptedIPAddressPing,
        'create-keytab-form': actions.createKeytab,
        'adopted-service-form': () => actions.startAdoptedService(state.selectedAdoptedService),
        'stored-adoption-config-form': actions.submitStoredAdoptionConfigurationDraft,
        'stored-config-copy-form': actions.copyStoredAdoptionConfiguration,
        'stored-script-form': actions.submitStoredScript,
        'adopted-script-form': actions.submitAdoptedScript,
    };

    async function handleStoredConfigClick(target) {
        const copyLabel = target.dataset.stageCopyStoredConfig;
        if (copyLabel) {
            state.pendingCopyStoredConfig = copyLabel;
            state.pendingDeleteStoredConfig = '';
            state.storedConfigCopyLabel = '';
            state.storedConfigsError = '';
            state.storedConfigNotice = '';
            render();
            return true;
        }
        if ('cancelCopyStoredConfig' in target.dataset) {
            state.pendingCopyStoredConfig = '';
            state.storedConfigCopyLabel = '';
            render();
            return true;
        }
        if ('newStoredConfig' in target.dataset) {
            resetStoredConfigEditor();
            return true;
        }
        if (target.dataset.editStoredConfig) {
            selectStoredConfigEditor(target.dataset.editStoredConfig);
            return true;
        }
        if (target.dataset.stageDeleteStoredConfig) {
            state.pendingCopyStoredConfig = '';
            state.storedConfigCopyLabel = '';
            stagePending('pendingDeleteStoredConfig', target.dataset.stageDeleteStoredConfig);
            return true;
        }
        if (target.dataset.confirmDeleteStoredConfig) {
            await actions.deleteStoredAdoptionConfiguration(target.dataset.confirmDeleteStoredConfig);
            return true;
        }
        if ('cancelDeleteStoredConfig' in target.dataset) {
            clearPending('pendingDeleteStoredConfig');
            return true;
        }
        return false;
    }

    async function handleStoredScriptClick(target) {
        const pendingKey = state.activeScriptKind === SCRIPT_KIND_GENERIC
            ? 'pendingDeleteGenericScript'
            : 'pendingDeleteStoredScript';
        if (target.dataset.stageDeleteStoredScript) {
            stagePending(pendingKey, target.dataset.stageDeleteStoredScript);
            return true;
        }
        if (target.dataset.confirmDeleteStoredScript) {
            await actions.deleteStoredScript(target.dataset.confirmDeleteStoredScript);
            return true;
        }
        if ('cancelDeleteStoredScript' in target.dataset) {
            clearPending(pendingKey);
            return true;
        }
        return false;
    }

    function openModule(moduleName) {
        if (state.view === MODULE_KEYTAB && moduleName !== MODULE_KEYTAB) {
            state.keytabForm.password = '';
        }

        const group = {
            [MODULE_GLOBAL_SCRIPTING]: 'scripting',
            [MODULE_TRANSPORT_SCRIPTS]: 'scripting',
            [MODULE_OPERATIONS]: 'networkActions',
            [MODULE_SERVICES]: 'networkActions',
            [MODULE_KEYTAB]: 'offlineTools',
        }[moduleName];
        if (group) {
            state.navigationGroupsExpanded[group] = true;
        }

        state.view = moduleName;

        if (moduleName === MODULE_IDENTITIES) {
            syncInterfaceName(state.storedConfigEditor);
            resetAdoptedInteractionState();
            render();

            ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
            if (!state.interfaceSelection && !state.interfaceSelectionLoading) {
                actions.loadInterfaceSelection();
            }
            return;
        }

        if (moduleName === MODULE_TRANSPORT_SCRIPTS) {
            activateScriptKind(SCRIPT_KIND_TRANSPORT);
            return;
        }

        if (moduleName === MODULE_GLOBAL_SCRIPTING) {
            state.selectedGlobalScriptingTab = GLOBAL_SCRIPTING_TAB_EDITOR;
            activateScriptKind(SCRIPT_KIND_GENERIC);
            return;
        }

        if (moduleName === MODULE_OPERATIONS) {
            state.dnsError = '';
            render();
            return;
        }

        if (moduleName === MODULE_KEYTAB) {
            state.keytabError = '';
            render();
            return;
        }

        if (moduleName === MODULE_SERVICES) {
            state.adoptedServiceError = '';
            state.adoptedServiceNotice = '';
            render();
            if (state.selectedServiceSourceIP) {
                actions.loadAdoptedIPAddressDetails(state.selectedServiceSourceIP, {selectedKey: 'selectedServiceSourceIP'});
            }
            return;
        }

        render();
    }

    async function openAdoptedIPAddress(ip) {
        state.selectedAdoptedIP = ip;
        resetAdoptedViewState();
        state.view = VIEW_ADOPTED_IP;
        render();
        ensureLoaded('storedScriptsLoaded', 'storedScriptsLoading', actions.loadStoredScripts);
        await actions.loadAdoptedIPAddressDetails(ip);
    }

    const draftFields = [
        ['dnsField', () => state.dnsForm, () => { state.dnsError = ''; }],
        ['pingField', () => state.pingForm, () => { state.pingError = ''; }],
        ['keytabField', () => state.keytabForm, () => { state.keytabError = ''; }],
        ['storedConfigField', () => state.storedConfigEditor, () => {
            state.storedConfigsError = '';
            state.storedConfigNotice = '';
        }],
        ['scriptField', () => state.scriptEditor, () => {
            if (state.activeScriptKind === SCRIPT_KIND_GENERIC) {
                state.genericScriptsError = '';
                state.genericScriptNotice = '';
            } else {
                state.storedScriptsError = '';
                state.storedScriptNotice = '';
            }
        }],
    ];

    function updateDraftField(target) {
        const draft = draftFields.find(([key]) => key in target.dataset);
        if (draft) {
            const [key, form, reset] = draft;
            form()[target.dataset[key]] = target.value;
            reset?.();
        } else if (target.dataset.keytabEncryptionType) {
            const type = target.dataset.keytabEncryptionType;
            state.keytabForm.encryptionTypes = target.checked
                ? [...new Set([...state.keytabForm.encryptionTypes, type])]
                : state.keytabForm.encryptionTypes.filter((current) => current !== type);
            state.keytabError = '';
        } else if ('storedConfigCopyLabel' in target.dataset) {
            state.storedConfigCopyLabel = target.value;
            state.storedConfigsError = '';
            state.storedConfigNotice = '';
        } else if ('operationSourceIp' in target.dataset) {
            state.selectedOperationSourceIP = target.value;
            state.dnsError = '';
            state.dnsResult = null;
            state.pingError = '';
            state.pingResult = null;
        } else if ('serviceSourceIp' in target.dataset) {
            state.selectedServiceSourceIP = target.value;
            state.adoptedServiceError = '';
            state.adoptedServiceNotice = '';
            actions.loadAdoptedIPAddressDetails(state.selectedServiceSourceIP, {selectedKey: 'selectedServiceSourceIP'});
        } else if (target.dataset.adoptedServiceField) {
            const serviceName = target.dataset.adoptedServiceName || state.selectedAdoptedService;
            state.adoptedServiceForms[serviceName][target.dataset.adoptedServiceField] = target.value;
            state.adoptedServiceError = '';
            state.adoptedServiceNotice = '';
        } else if ('adoptedTransportScriptName' in target.dataset) {
            state.adoptedTransportScriptName = target.value;
            state.adoptedScriptError = '';
        } else if ('genericRunScriptName' in target.dataset) {
            state.selectedGenericRunScriptName = target.value;
            state.genericScriptRunError = '';
            state.genericScriptRunResult = null;
        }
    }

    async function handleClick(event) {
        const target = event.target.closest('button, wa-button');

        if (target) {
            if ('toggleSidebar' in target.dataset) {
                state.navigationCollapsed = !state.navigationCollapsed;
                render();
                return;
            }
            if (target.dataset.openModule) {
                openModule(target.dataset.openModule);
                return;
            }
            if (target.dataset.openAdoptedIp) {
                await openAdoptedIPAddress(target.dataset.openAdoptedIp);
                return;
            }
            if (target.dataset.adoptStoredConfig) {
                await actions.submitStoredAdoption(target.dataset.adoptStoredConfig);
                return;
            }
            if (await handleStoredConfigClick(target) || await handleStoredScriptClick(target)) {
                return;
            }
            const command = buttonCommands.find(([key]) => key in target.dataset);
            if (command) {
                await command[1]();
                return;
            }
            if (target.dataset.releaseAdoption) {
                await actions.releaseAdoption(target.dataset.releaseAdoption);
                return;
            }
            if (target.dataset.stopAdoptedService) {
                await actions.stopAdoptedService(target.dataset.stopAdoptedService);
                return;
            }
            if ('chooseServiceDirectory' in target.dataset) {
                await actions.chooseServiceDirectoryField(
                    target.dataset.adoptedServiceName || state.selectedAdoptedService,
                    target.dataset.adoptedServiceField || '',
                );
                return;
            }
            return;
        }

    }

    function handleFieldEdit(event) {
        const target = event.target;
        if ('storedScriptSelection' in target.dataset) {
            if (event.type === 'change') {
                actions.loadStoredScriptDocument(target.value);
            }
            return;
        }
        if ('serviceSourceIp' in target.dataset && event.type !== 'change') {
            return;
        }
        if (target.dataset.scriptEditorPreference) {
            if (event.type !== 'change') {
                return;
            }
            state.scriptEditorPreferences[target.dataset.scriptEditorPreference] = target.value;
            persistScriptEditorPreferences();
            render();
            return;
        }
        updateDraftField(target);
    }

    function handleTabChange(event) {
        if (event.target.matches('[data-operation-tabs]')) {
            state.selectedOperationTab = event.detail.name;
        } else if (event.target.matches('[data-global-scripting-tabs]') && state.selectedGlobalScriptingTab !== event.detail.name) {
            state.selectedGlobalScriptingTab = event.detail.name === GLOBAL_SCRIPTING_TAB_RUN
                ? GLOBAL_SCRIPTING_TAB_RUN
                : GLOBAL_SCRIPTING_TAB_EDITOR;
            render();
        } else if (event.target.matches('[data-service-tabs]') && state.selectedAdoptedService !== event.detail.name) {
            state.selectedAdoptedService = event.detail.name;
            state.adoptedServiceError = '';
            state.adoptedServiceNotice = '';
            render();
        }
    }

    function handleNavigationSelection(event) {
        if (!event.target.matches('wa-tree')) {
            return;
        }
        const [selection] = event.detail.selection || [];
        if (selection?.dataset.openModule) {
            openModule(selection.dataset.openModule);
        }
    }

    function handleNavigationExpansion(event) {
        const group = event.target.dataset.navigationGroup;
        if (!group) {
            return;
        }
        state.navigationGroupsExpanded[group] = event.type === 'wa-expand';
    }

    async function handleSubmit(event) {
        const form = event.target;
        const submit = formActions[form.id];
        if (submit) {
            event.preventDefault();
            await submit(form);
        }
    }

    function attachEventDelegates() {
        root.addEventListener('click', handleClick);
        root.addEventListener('input', handleFieldEdit);
        root.addEventListener('change', handleFieldEdit);
        root.addEventListener('wa-tab-show', handleTabChange);
        root.addEventListener('wa-selection-change', handleNavigationSelection);
        root.addEventListener('wa-expand', handleNavigationExpansion);
        root.addEventListener('wa-collapse', handleNavigationExpansion);
        root.addEventListener('submit', handleSubmit);
        EventsOn('kraken:generic-script-output', (event = {}) => {
            appendGenericScriptOutput(event.stream, event.text);
            scheduleOutputRender();
        });
    }

    async function initialize() {
        attachEventDelegates();
        loadScriptEditorPreferences();
        render();
        await Promise.all([
            actions.loadConfigurationDirectory({render: false}),
            actions.loadAdoptedIPAddresses({render: false}),
            actions.loadInterfaceSelection({render: false}),
            actions.loadStoredAdoptionConfigurations({render: false}),
        ]);
        render();
    }

    initialize();
}
