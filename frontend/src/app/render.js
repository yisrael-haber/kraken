import {renderAdoptedIPAddressView, renderOperationsModule, renderServicesModule} from '../ui/adoption';
import {renderScriptsModule} from '../ui/scripts';
import {renderIdentitiesModule} from '../ui/identities';
import {renderKeytabModule} from '../ui/keytab';
import {renderAppShell} from '../ui/shell';
import {
    availableInterfaceOptions,
    MODULE_GLOBAL_SCRIPTING,
    MODULE_OPERATIONS,
    MODULE_KEYTAB,
    MODULE_SERVICES,
    MODULE_IDENTITIES,
    MODULE_TRANSPORT_SCRIPTS,
    state,
    VIEW_ADOPTED_IP,
} from './state';

export function createRender(root, {logo}) {
    return function render() {
        let content;
        switch (state.view) {
        case MODULE_TRANSPORT_SCRIPTS:
        case MODULE_GLOBAL_SCRIPTING:
            content = renderScriptsModule({state});
            break;
        case MODULE_IDENTITIES:
            content = renderIdentitiesModule({
                interfaceOptions: availableInterfaceOptions(),
                state,
            });
            break;
        case MODULE_OPERATIONS:
            content = renderOperationsModule({state});
            break;
        case MODULE_SERVICES: {
            const selectedServiceDetails = state.adoptedDetails?.ip === state.selectedServiceSourceIP ? state.adoptedDetails : null;
            content = renderServicesModule({
                details: selectedServiceDetails,
                state,
            });
            break;
        }
        case MODULE_KEYTAB:
            content = renderKeytabModule({state});
            break;
        case VIEW_ADOPTED_IP: {
            const selectedAdoptedItem = state.adoptedItems.find((item) => item.ip === state.selectedAdoptedIP) || null;
            const selectedAdoptedDetails = state.adoptedDetails?.ip === state.selectedAdoptedIP ? state.adoptedDetails : null;
            content = renderAdoptedIPAddressView({
                details: selectedAdoptedDetails,
                item: selectedAdoptedItem,
                state,
            });
            break;
        }
        default:
            state.view = MODULE_IDENTITIES;
            content = renderIdentitiesModule({
                interfaceOptions: availableInterfaceOptions(),
                state,
            });
            break;
        }

        root.innerHTML = renderAppShell({content, logo, state});
    };
}
