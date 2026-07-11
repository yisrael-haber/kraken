import {renderAdoptIPAddressForm, renderAdoptedIPAddressView, renderOperationsModule, renderServicesModule} from '../ui/adoption';
import {renderModuleHome} from '../ui/home';
import {renderScriptsModule} from '../ui/scripts';
import {renderStoredAdoptionsModule} from '../ui/storedAdoptions';
import {renderOfflineModule} from '../ui/offline';
import {
    availableInterfaceOptions,
    MODULE_GLOBAL_SCRIPTING,
    MODULE_OPERATIONS,
    MODULE_OFFLINE,
    MODULE_SERVICES,
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
        case MODULE_OPERATIONS:
            root.innerHTML = renderOperationsModule({state});
            break;
        case MODULE_SERVICES: {
            const selectedServiceDetails = state.adoptedDetails?.ip === state.selectedServiceSourceIP ? state.adoptedDetails : null;
            root.innerHTML = renderServicesModule({
                details: selectedServiceDetails,
                state,
            });
            break;
        }
        case MODULE_OFFLINE:
            root.innerHTML = renderOfflineModule({state});
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
                moduleOperations: MODULE_OPERATIONS,
                moduleServices: MODULE_SERVICES,
                moduleOffline: MODULE_OFFLINE,
                state,
            });
            break;
        }
    };
}
