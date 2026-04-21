import {renderAdoptIPAddressForm, renderAdoptedIPAddressView} from '../ui/adoption';
import {renderModuleHome} from '../ui/home';
import {renderRoutingModule} from '../ui/routing';
import {renderScriptsModule} from '../ui/scripts';
import {renderStoredAdoptionsModule} from '../ui/storedAdoptions';
import {
    availableInterfaceOptions,
    MODULE_ROUTING,
    MODULE_SCRIPTS,
    MODULE_STORED_ADOPTIONS,
    state,
    VIEW_ADOPT_FORM,
    VIEW_ADOPTED_IP,
} from './state';

export function createRender(root, {logo}) {
    return function render() {
        switch (state.view) {
        case MODULE_ROUTING:
            root.innerHTML = renderRoutingModule({state});
            break;
        case MODULE_SCRIPTS:
            root.innerHTML = renderScriptsModule({state});
            break;
        case MODULE_STORED_ADOPTIONS:
            root.innerHTML = renderStoredAdoptionsModule({
                interfaceOptions: availableInterfaceOptions(state.storedConfigEditor.interfaceName),
                state,
            });
            break;
        case VIEW_ADOPT_FORM:
            root.innerHTML = renderAdoptIPAddressForm({interfaceOptions: availableInterfaceOptions(), state});
            break;
        case VIEW_ADOPTED_IP: {
            const selectedAdoptedItem = state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null;
            const selectedAdoptedDetails = state.adoptedDetails?.ip === state.selectedAdoptedIP ? state.adoptedDetails : null;
            root.innerHTML = renderAdoptedIPAddressView({
                interfaceOptions: availableInterfaceOptions(state.adoptedEditForm.interfaceName || selectedAdoptedItem?.interfaceName || ''),
                details: selectedAdoptedDetails,
                item: selectedAdoptedItem,
                state,
            });
            break;
        }
        default:
            root.innerHTML = renderModuleHome({
                logo,
                moduleRouting: MODULE_ROUTING,
                moduleStoredAdoptions: MODULE_STORED_ADOPTIONS,
                moduleScripts: MODULE_SCRIPTS,
                state,
            });
            break;
        }
    };
}
