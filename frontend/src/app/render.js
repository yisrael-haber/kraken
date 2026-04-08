import {renderAdoptIPAddressForm, renderAdoptedIPAddressView} from '../ui/adoption';
import {renderModuleHome} from '../ui/home';
import {renderLocalNetworkModule} from '../ui/localNetwork';
import {renderPacketOverridesModule} from '../ui/overrides';
import {renderScriptsModule} from '../ui/scripts';
import {renderStoredAdoptionsModule} from '../ui/storedAdoptions';
import {PACKET_OVERRIDE_SCHEMA} from '../packetOverrideModel';
import {
    adoptableInterfaces,
    filteredInterfaces,
    getSelectedAdoptedIPAddress,
    getSelectedAdoptedIPAddressDetails,
    getSelectedInterface,
    MODULE_LOCAL_NETWORK,
    MODULE_PACKET_OVERRIDES,
    MODULE_JS_SCRIPTS,
    MODULE_STORED_ADOPTIONS,
    state,
    VIEW_ADOPT_FORM,
    VIEW_ADOPTED_IP,
} from './state';

export function createRender(root, {logo}) {
    return function render(options = {}) {
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
        case MODULE_JS_SCRIPTS:
            root.innerHTML = renderScriptsModule({state});
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
                moduleJSScripts: MODULE_JS_SCRIPTS,
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
    };
}
