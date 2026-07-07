import {renderAdoptIPAddressForm, renderAdoptedIPAddressView} from '../ui/adoption';
import {renderModuleHome} from '../ui/home';
import {renderScriptsModule} from '../ui/scripts';
import {renderStoredAdoptionsModule} from '../ui/storedAdoptions';
import {
    availableInterfaceOptions,
    MODULE_GLOBAL_SCRIPTING,
    MODULE_STORED_ADOPTIONS,
    MODULE_TRANSPORT_SCRIPTS,
    state,
    VIEW_ADOPT_FORM,
    VIEW_ADOPTED_IP,
} from './state';

export function createRender(root, {logo}) {
    return function render() {
        switch (state.view) {
        case MODULE_TRANSPORT_SCRIPTS:
        case MODULE_GLOBAL_SCRIPTING:
            root.innerHTML = renderScriptsModule({state});
            break;
        case MODULE_STORED_ADOPTIONS:
            root.innerHTML = renderStoredAdoptionsModule({
                interfaceOptions: availableInterfaceOptions(),
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
                details: selectedAdoptedDetails,
                item: selectedAdoptedItem,
                state,
            });
            break;
        }
        default:
            root.innerHTML = renderModuleHome({
                logo,
                moduleStoredAdoptions: MODULE_STORED_ADOPTIONS,
                moduleTransportScripts: MODULE_TRANSPORT_SCRIPTS,
                moduleGlobalScripting: MODULE_GLOBAL_SCRIPTING,
                state,
            });
            break;
        }
    };
}
