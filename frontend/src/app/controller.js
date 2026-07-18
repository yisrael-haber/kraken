import {syncScriptCodeEditor} from '../scriptCodeEditor';
import {createScriptEditor, SCRIPT_KIND_GENERIC, SCRIPT_KIND_TRANSPORT} from '../scriptModel';
import {EventsOn} from '../../wailsjs/runtime/runtime';
import {createActions} from './actions';
import {createRender} from './render';
import {
    ADOPT_MODE_STORED,
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
    MODULE_OFFLINE,
    MODULE_OPERATIONS,
    MODULE_SERVICES,
    MODULE_STORED_ADOPTIONS,
    MODULE_TRANSPORT_SCRIPTS,
    loadScriptEditorPreferences,
    persistScriptEditorPreferences,
    VIEW_ADOPTED_IP,
    VIEW_ADOPT_FORM,
    VIEW_HOME,
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

    function ensureInterfaceSelectionLoaded(options = {}) {
        if (!state.interfaceSelection && !state.interfaceSelectionLoading) {
            actions.loadInterfaceSelection(options);
        }
    }

    function resetStoredEditor({selectedKey, pendingKey, noticeKey, errorKey, editorKey, createEditor, sync}) {
        state[selectedKey] = '';
        state[pendingKey] = '';
        state[noticeKey] = '';
        state[errorKey] = '';
        state[editorKey] = editorKey === 'scriptEditor' ? createEditor(null, state.activeScriptKind) : createEditor();
        if (editorKey === 'storedConfigEditor') {
            state.pendingCopyStoredConfig = '';
            state.storedConfigCopyLabel = '';
        }
        sync?.();
        render();
    }

    function selectStoredEditor(items, field, value, {selectedKey, pendingKey, noticeKey, errorKey, editorKey, createEditor}) {
        const selected = findByField(items, field, value);
        if (!selected) {
            return false;
        }

        state[selectedKey] = selected[field];
        state[pendingKey] = '';
        state[noticeKey] = '';
        state[errorKey] = '';
        state[editorKey] = createEditor(selected);
        if (editorKey === 'storedConfigEditor') {
            state.pendingCopyStoredConfig = '';
            state.storedConfigCopyLabel = '';
        }
        render();
        return true;
    }

    function stagePending(stateKey, value) {
        state[stateKey] = value;
        render();
    }

    function clearPending(stateKey) {
        state[stateKey] = '';
        render();
    }

    function goHome() {
        state.view = VIEW_HOME;
        state.adoptError = '';
        state.storedConfigNotice = '';
        state.storedScriptNotice = '';
        state.pendingCopyStoredConfig = '';
        state.storedConfigCopyLabel = '';
        state.pendingDeleteStoredConfig = '';
        state.pendingDeleteStoredScript = '';
        resetAdoptedInteractionState();
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
        ['cancelDeleteAdoption', () => clearPending('pendingDeleteAdoption')],
        ['goHome', goHome],
    ];

    const formActions = {
        'adopt-ip-form': (form) => actions.submitAdoption(new FormData(form)),
        'adopted-mtu-form': (form) => actions.submitAdoptedMTU(new FormData(form)),
        'adopted-ip-dns-form': (form) => actions.submitAdoptedIPAddressDNS(new FormData(form)),
        'adopted-ip-ping-form': (form) => actions.submitAdoptedIPAddressPing(new FormData(form)),
        'create-keytab-form': (form) => actions.createKeytab(new FormData(form)),
        'adopted-service-form': () => actions.startAdoptedService(state.selectedAdoptedService),
        'stored-adoption-config-form': actions.submitStoredAdoptionConfigurationDraft,
        'stored-config-copy-form': (form) => actions.copyStoredAdoptionConfiguration(new FormData(form)),
        'stored-script-form': actions.submitStoredScript,
        'adopted-script-form': actions.submitAdoptedScript,
    };

    const storedEditors = [
        {
            suffix: 'Config',
            itemsKey: 'storedConfigs',
            field: 'label',
            selectedKey: 'selectedStoredConfigLabel',
            noticeKey: 'storedConfigNotice',
            errorKey: 'storedConfigsError',
            editorKey: 'storedConfigEditor',
            createEditor: createStoredConfigEditor,
            sync: () => syncInterfaceName(state.storedConfigEditor),
            deleteAction: actions.deleteStoredAdoptionConfiguration,
        },
        {
            suffix: 'Script',
            itemsKey: 'storedScripts',
            field: 'name',
            selectedKey: 'selectedStoredScriptKey',
            noticeKey: 'storedScriptNotice',
            errorKey: 'storedScriptsError',
            editorKey: 'scriptEditor',
            createEditor: createScriptEditor,
            editAction: actions.loadStoredScriptDocument,
            deleteAction: actions.deleteStoredScript,
        },
    ];

    function pendingKeyForStoredEditor(editor) {
        if (editor.suffix === 'Script' && state.activeScriptKind === SCRIPT_KIND_GENERIC) {
            return 'pendingDeleteGenericScript';
        }
        return `pendingDeleteStored${editor.suffix}`;
    }

    async function handleStoredEditorClick(target) {
        for (const baseEditor of storedEditors) {
            const editor = baseEditor.suffix === 'Script' && state.activeScriptKind === SCRIPT_KIND_GENERIC
                ? {
                    ...baseEditor,
                    itemsKey: 'genericScripts',
                    selectedKey: 'selectedGenericScriptKey',
                    noticeKey: 'genericScriptNotice',
                    errorKey: 'genericScriptsError',
                }
                : baseEditor;
            const pendingKey = pendingKeyForStoredEditor(editor);

            if (editor.suffix === 'Config') {
                const copyValue = target.dataset.stageCopyStoredConfig;
                if (copyValue) {
                    state.pendingCopyStoredConfig = copyValue;
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
            }

            if (`newStored${editor.suffix}` in target.dataset) {
                resetStoredEditor({...editor, pendingKey});
                return true;
            }

            const editValue = target.dataset[`editStored${editor.suffix}`];
            if (editValue) {
                if (editor.editAction) {
                    await editor.editAction(editValue);
                } else {
                    selectStoredEditor(state[editor.itemsKey], editor.field, editValue, {...editor, pendingKey});
                }
                return true;
            }

            const stageDeleteValue = target.dataset[`stageDeleteStored${editor.suffix}`];
            if (stageDeleteValue) {
                if (editor.suffix === 'Config') {
                    state.pendingCopyStoredConfig = '';
                    state.storedConfigCopyLabel = '';
                }
                stagePending(pendingKey, stageDeleteValue);
                return true;
            }

            const confirmDeleteValue = target.dataset[`confirmDeleteStored${editor.suffix}`];
            if (confirmDeleteValue) {
                await editor.deleteAction(confirmDeleteValue);
                return true;
            }

            if (`cancelDeleteStored${editor.suffix}` in target.dataset) {
                clearPending(pendingKey);
                return true;
            }
        }

        return false;
    }

    function openModule(moduleName) {
        state.view = moduleName;

        if (moduleName === MODULE_STORED_ADOPTIONS) {
            syncInterfaceName(state.storedConfigEditor);
            render();

            ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
            ensureInterfaceSelectionLoaded();
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

        if (moduleName === MODULE_OFFLINE) {
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

    function openAdoptForm() {
        state.view = VIEW_ADOPT_FORM;
        state.adoptMode = ADOPT_MODE_STORED;
        state.adoptError = '';
        state.storedConfigsError = '';
        syncInterfaceName(state.adoptForm);
        render();

        ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
        ensureInterfaceSelectionLoaded();
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
        ['adoptField', () => state.adoptForm],
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
            if (target.dataset.openAdoptedIp) {
                await openAdoptedIPAddress(target.dataset.openAdoptedIp);
                return;
            }
            if (target.dataset.adoptedServiceTab) {
                state.selectedAdoptedService = target.dataset.adoptedServiceTab;
                render();
                return;
            }
            if (target.dataset.globalScriptingTab) {
                state.selectedGlobalScriptingTab = target.dataset.globalScriptingTab === GLOBAL_SCRIPTING_TAB_RUN
                    ? GLOBAL_SCRIPTING_TAB_RUN
                    : GLOBAL_SCRIPTING_TAB_EDITOR;
                render();
                return;
            }
            if (target.dataset.adoptMode) {
                state.adoptMode = target.dataset.adoptMode;
                state.adoptError = '';
                render();
                if (state.adoptMode === ADOPT_MODE_STORED) {
                    ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
                }
                return;
            }
            if (target.dataset.adoptStoredConfig) {
                await actions.submitStoredAdoption(target.dataset.adoptStoredConfig);
                return;
            }
            if (await handleStoredEditorClick(target)) {
                return;
            }
            const command = buttonCommands.find(([key]) => key in target.dataset);
            if (command) {
                await command[1]();
                return;
            }
            if ('refreshAdoptedDetails' in target.dataset) {
                if (state.selectedAdoptedIP) {
                    await actions.loadAdoptedIPAddressDetails(state.selectedAdoptedIP);
                }
                return;
            }
            if (target.dataset.stageDeleteAdoption) {
                stagePending('pendingDeleteAdoption', target.dataset.stageDeleteAdoption);
                return;
            }
            if (target.dataset.confirmDeleteAdoption) {
                await actions.deleteAdoption(target.dataset.confirmDeleteAdoption);
                return;
            }
            if (target.dataset.startAdoptedService) {
                await actions.startAdoptedService(target.dataset.startAdoptedService);
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

    function handleFieldEdit(event) {
        const target = event.target;
        if (target.dataset.scriptEditorPreference) {
            state.scriptEditorPreferences[target.dataset.scriptEditorPreference] = target.value;
            persistScriptEditorPreferences();
            render();
            return;
        }
        updateDraftField(target);
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
        root.addEventListener('keydown', handleKeydown);
        root.addEventListener('input', handleFieldEdit);
        root.addEventListener('change', handleFieldEdit);
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
        ]);
        render();
    }

    initialize();
}
