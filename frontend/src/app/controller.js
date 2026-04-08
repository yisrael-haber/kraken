import {
    createPacketOverrideEditor,
    defaultOverrideFieldValue,
    PACKET_OVERRIDE_SCHEMA,
} from '../packetOverrideModel';
import {syncScriptCodeEditor} from '../scriptCodeEditor';
import {createScriptEditor} from '../scriptModel';
import {createActions} from './actions';
import {createRender} from './render';
import {
    ADOPT_MODE_STORED,
    ADOPTED_TAB_INFO,
    createStoredConfigEditor,
    DEFAULT_PING_FORM,
    findByField,
    populateAdoptedEditForm,
    populateAdoptedOverrideBindings,
    state,
    syncAdoptionFormInterface,
    syncStoredConfigEditorInterface,
    MODULE_JS_SCRIPTS,
    MODULE_LOCAL_NETWORK,
    MODULE_PACKET_OVERRIDES,
    MODULE_STORED_ADOPTIONS,
    loadScriptEditorPreferences,
    persistScriptEditorPreferences,
    VIEW_ADOPTED_IP,
    VIEW_ADOPT_FORM,
    VIEW_HOME,
} from './state';

export function startApp(root, {logo}) {
    const baseRender = createRender(root, {logo});

    function render(options = {}) {
        baseRender(options);
        syncScriptCodeEditor(root, state);
    }

    const actions = createActions(render);

    function ensureLoaded(loadedKey, loadingKey, loader, options = {}) {
        if (!state[loadedKey] && !state[loadingKey]) {
            loader(options);
        }
    }

    function ensureInterfacesLoaded(options = {}) {
        if (!state.snapshot && !state.interfacesLoading) {
            actions.loadInterfaces(options);
        }
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

            ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
            ensureInterfacesLoaded();
            return;
        }

        if (moduleName === MODULE_PACKET_OVERRIDES) {
            render();
            ensureLoaded('storedOverridesLoaded', 'storedOverridesLoading', actions.loadStoredPacketOverrides);
            return;
        }

        if (moduleName === MODULE_JS_SCRIPTS) {
            render();
            ensureLoaded('storedScriptsLoaded', 'storedScriptsLoading', actions.loadStoredScripts);
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

        ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations);
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
        populateAdoptedEditForm(state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null);
        state.view = VIEW_ADOPTED_IP;
        render();
        ensureLoaded('storedConfigsLoaded', 'storedConfigsLoading', actions.loadStoredAdoptionConfigurations, {render: false});
        ensureLoaded('storedOverridesLoaded', 'storedOverridesLoading', actions.loadStoredPacketOverrides, {render: false});
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
                await actions.deleteStoredAdoptionConfiguration(target.dataset.confirmDeleteStoredConfig);
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
                await actions.deleteStoredPacketOverride(target.dataset.confirmDeleteStoredOverride);
                return;
            }
            if ('newStoredScript' in target.dataset) {
                state.selectedStoredScriptName = '';
                state.pendingDeleteStoredScript = '';
                state.storedScriptNotice = '';
                state.storedScriptsError = '';
                state.scriptEditor = createScriptEditor();
                render();
                return;
            }
            if (target.dataset.editStoredScript) {
                await actions.loadStoredScriptDocument(target.dataset.editStoredScript);
                return;
            }
            if (target.dataset.refreshStoredScripts) {
                await actions.refreshStoredScriptsInventory();
                return;
            }
            if (target.dataset.stageDeleteStoredScript) {
                state.pendingDeleteStoredScript = target.dataset.stageDeleteStoredScript;
                render();
                return;
            }
            if (target.dataset.confirmDeleteStoredScript) {
                await actions.deleteStoredScript(target.dataset.confirmDeleteStoredScript);
                return;
            }
            if ('refreshAdoptedDetails' in target.dataset) {
                if (state.selectedAdoptedIP) {
                    await actions.loadAdoptedIPAddressDetails(state.selectedAdoptedIP);
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
                await actions.clearAdoptedActivity(target.dataset.confirmClearAdoptedActivity);
                return;
            }
            if (target.dataset.confirmDeleteAdoption) {
                await actions.deleteAdoption(target.dataset.confirmDeleteAdoption);
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
            if ('cancelDeleteStoredScript' in target.dataset) {
                state.pendingDeleteStoredScript = '';
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
                state.storedScriptNotice = '';
                state.adoptedOverrideBindingsError = '';
                state.pingError = '';
                state.pingResult = null;
                state.pendingClearAdoptedActivity = '';
                state.pendingDeleteAdoption = '';
                state.pendingDeleteStoredConfig = '';
                state.pendingDeleteStoredOverride = '';
                state.pendingDeleteStoredScript = '';
                render();
                return;
            }
            if (target.dataset.interface) {
                state.selectedName = target.dataset.interface;
                render();
                return;
            }
            if ('resetAdoptedEdit' in target.dataset) {
                populateAdoptedEditForm(state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null);
                state.adoptedUpdateError = '';
                render();
                return;
            }
            if (target.id === 'refresh-interfaces') {
                actions.loadInterfaces({preserveSelection: true});
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

        if (form.id === 'stored-packet-override-form') {
            event.preventDefault();
            await actions.submitStoredPacketOverride();
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

        if (form.id === 'adopted-arp-override-form' || form.id === 'adopted-icmp-override-form') {
            event.preventDefault();
            await actions.submitAdoptedOverrideBindings();
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
            actions.loadInterfaces({render: false}),
            actions.loadAdoptedIPAddresses({render: false}),
        ]);
        render();
    }

    initialize();
}
