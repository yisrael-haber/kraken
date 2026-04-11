import {syncScriptCodeEditor} from '../scriptCodeEditor';
import {createScriptEditor} from '../scriptModel';
import {createActions} from './actions';
import {createRender} from './render';
import {
    ADOPT_MODE_STORED,
    createStoredConfigEditor,
    findByField,
    populateAdoptedEditForm,
    resetAdoptedInteractionState,
    resetAdoptedViewState,
    state,
    syncAdoptFormInterfaceName,
    syncStoredConfigInterfaceName,
    MODULE_SCRIPTS,
    MODULE_STORED_ADOPTIONS,
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
        state[editorKey] = createEditor();
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
        state.pendingDeleteStoredConfig = '';
        state.pendingDeleteStoredScript = '';
        resetAdoptedInteractionState();
        render();
    }

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
            sync: syncStoredConfigInterfaceName,
            deleteAction: actions.deleteStoredAdoptionConfiguration,
        },
        {
            suffix: 'Script',
            selectedKey: 'selectedStoredScriptName',
            noticeKey: 'storedScriptNotice',
            errorKey: 'storedScriptsError',
            editorKey: 'scriptEditor',
            createEditor: createScriptEditor,
            editAction: actions.loadStoredScriptDocument,
            deleteAction: actions.deleteStoredScript,
        },
    ];

    function pendingKeyForStoredEditor(editor) {
        return `pendingDeleteStored${editor.suffix}`;
    }

    async function handleStoredEditorClick(target) {
        for (const editor of storedEditors) {
            const pendingKey = pendingKeyForStoredEditor(editor);

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
            syncStoredConfigInterfaceName();
            render();

            ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
            ensureInterfaceSelectionLoaded();
            return;
        }

        if (moduleName === MODULE_SCRIPTS) {
            ensureLoaded('storedScriptsLoaded', 'storedScriptsLoading', actions.loadStoredScripts, {render: false});
            render();
            return;
        }

        render();
    }

    function openAdoptForm() {
        state.view = VIEW_ADOPT_FORM;
        state.adoptMode = ADOPT_MODE_STORED;
        state.adoptError = '';
        state.storedConfigsError = '';
        syncAdoptFormInterfaceName();
        render();

        ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
        ensureInterfaceSelectionLoaded();
    }

    async function openAdoptedIPAddress(ip) {
        const selectedItem = state.adoptedItems.find((item) => item.ip === ip) || null;
        state.selectedAdoptedIP = ip;
        resetAdoptedViewState(selectedItem);
        state.view = VIEW_ADOPTED_IP;
        render();
        ensureLoaded('storedScriptsLoaded', 'storedScriptsLoading', actions.loadStoredScripts, {render: false});
        await actions.loadAdoptedIPAddressDetails(ip);
    }

    function updateDraftField(target) {
        if (target.dataset.adoptField) {
            state.adoptForm[target.dataset.adoptField] = target.value;
        } else if (target.dataset.adoptedEditField) {
            state.adoptedEditForm[target.dataset.adoptedEditField] = target.value;
        } else if (target.dataset.pingField) {
            state.pingForm[target.dataset.pingField] = target.value;
            state.pingError = '';
        } else if ('adoptedScriptName' in target.dataset) {
            state.adoptedScriptName = target.value;
            state.adoptedScriptError = '';
        } else if (target.dataset.storedConfigField) {
            state.storedConfigEditor[target.dataset.storedConfigField] = target.value;
            state.storedConfigsError = '';
            state.storedConfigNotice = '';
        } else if (target.dataset.scriptField) {
            state.scriptEditor[target.dataset.scriptField] = target.value;
            state.storedScriptsError = '';
            state.storedScriptNotice = '';
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
            if (target.dataset.refreshStoredScripts) {
                await actions.refreshStoredScriptsInventory();
                return;
            }
            if ('refreshAdoptedDetails' in target.dataset) {
                if (state.selectedAdoptedIP) {
                    await actions.loadAdoptedIPAddressDetails(state.selectedAdoptedIP);
                }
                return;
            }
            if (target.dataset.stageClearAdoptedActivity) {
                stagePending('pendingClearAdoptedActivity', target.dataset.stageClearAdoptedActivity);
                return;
            }
            if (target.dataset.stageDeleteAdoption) {
                stagePending('pendingDeleteAdoption', target.dataset.stageDeleteAdoption);
                return;
            }
            if (target.dataset.confirmClearAdoptedActivity) {
                await actions.clearAdoptedActivity(target.dataset.confirmClearAdoptedActivity);
                return;
            }
            if (target.dataset.confirmDeleteAdoption) {
                await actions.deleteAdoption(target.dataset.confirmDeleteAdoption);
                return;
            }
            if ('startAdoptedRecording' in target.dataset) {
                await actions.startAdoptedIPAddressRecording();
                return;
            }
            if ('startAdoptedRecordingAs' in target.dataset) {
                await actions.startAdoptedIPAddressRecordingWithDialog();
                return;
            }
            if ('stopAdoptedRecording' in target.dataset) {
                await actions.stopAdoptedIPAddressRecording();
                return;
            }
            if ('cancelClearAdoptedActivity' in target.dataset) {
                clearPending('pendingClearAdoptedActivity');
                return;
            }
            if ('cancelDeleteAdoption' in target.dataset) {
                clearPending('pendingDeleteAdoption');
                return;
            }
            if ('goHome' in target.dataset) {
                goHome();
                return;
            }
            if ('resetAdoptedEdit' in target.dataset) {
                populateAdoptedEditForm(state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null);
                state.adoptedUpdateError = '';
                render();
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
        if (target.dataset.scriptEditorPreference) {
            state.scriptEditorPreferences[target.dataset.scriptEditorPreference] = target.value;
            persistScriptEditorPreferences();
            render();
            return;
        }

        updateDraftField(target);
    }

    function handleChange(event) {
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

        if (form.id === 'adopt-ip-form') {
            event.preventDefault();
            await actions.submitAdoption(new FormData(form));
            return;
        }

        if (form.id === 'adopted-ip-edit-form') {
            event.preventDefault();
            await actions.submitAdoptionUpdate(new FormData(form));
            return;
        }

        if (form.id === 'adopted-ip-ping-form') {
            event.preventDefault();
            await actions.submitAdoptedIPAddressPing(new FormData(form));
            return;
        }

        if (form.id === 'stored-adoption-config-form') {
            event.preventDefault();
            await actions.submitStoredAdoptionConfigurationDraft();
            return;
        }

        if (form.id === 'stored-script-form') {
            event.preventDefault();
            await actions.submitStoredScript();
            return;
        }

        if (form.id === 'adopted-script-form') {
            event.preventDefault();
            await actions.submitAdoptedScript();
        }
    }

    function attachEventDelegates() {
        root.addEventListener('click', handleClick);
        root.addEventListener('keydown', handleKeydown);
        root.addEventListener('input', handleInput);
        root.addEventListener('change', handleChange);
        root.addEventListener('submit', handleSubmit);
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
