import {renderAdoptIPAddressForm, renderAdoptedIPAddressView} from '../ui/adoption';
import {renderModuleHome} from '../ui/home';
import {renderScriptsModule} from '../ui/scripts';
import {renderStoredAdoptionsModule} from '../ui/storedAdoptions';
import {
    availableInterfaceOptions,
    getSelectedAdoptedIPAddress,
    getSelectedAdoptedIPAddressDetails,
    MODULE_SCRIPTS,
    MODULE_STORED_ADOPTIONS,
    state,
    VIEW_ADOPT_FORM,
    VIEW_ADOPTED_IP,
} from './state';

export function createRender(root, {logo}) {
    return function render() {
        switch (state.view) {
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
        case VIEW_ADOPTED_IP:
            root.innerHTML = renderAdoptedIPAddressView({
                interfaceOptions: availableInterfaceOptions(state.adoptedEditForm.interfaceName || getSelectedAdoptedIPAddress()?.interfaceName || ''),
                details: getSelectedAdoptedIPAddressDetails(),
                item: getSelectedAdoptedIPAddress(),
                state,
            });
            break;
        default:
            root.innerHTML = renderModuleHome({
                logo,
                moduleStoredAdoptions: MODULE_STORED_ADOPTIONS,
                moduleScripts: MODULE_SCRIPTS,
                state,
            });
            break;
        }
    };
}
