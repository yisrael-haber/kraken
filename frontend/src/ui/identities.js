import {
    renderIdentityFields,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {renderStoredConfigList} from './storedConfigs';

function renderStoredConfigEditor(interfaceOptions, state) {
    const selected = Boolean(state.selectedStoredConfigLabel);
    const busy = state.savingStoredConfig || state.copyingStoredConfig || state.deletingStoredConfigLabel || state.adoptingStoredLabel;
    const selectOptions = renderInterfaceOptions(
        interfaceOptions,
        'No adoptable interfaces available',
    );

    return `
        <section class="stored-identity-editor wa-stack wa-gap-s">
            <header class="section-heading wa-split wa-gap-xs"><h2 class="wa-heading-m">${selected ? 'Edit identity' : 'New identity'}</h2></header>
            <form id="stored-adoption-config-form" class="identity-editor-form wa-stack wa-gap-s">
                <div class="identity-editor-fields wa-grid wa-gap-s">
                    ${renderIdentityFields({
                        disabled: busy,
                        disabledFields: selected ? ['label'] : [],
                        form: state.storedConfigEditor,
                        interfaceOptions: selectOptions,
                        dataAttribute: 'data-stored-config-field',
                        order: ['label', 'ip', 'subnetPrefix', 'interfaceName', 'defaultGateway', 'mac', 'mtu'],
                    })}
                </div>

                <div class="form-actions wa-cluster wa-gap-xs wa-justify-content-end">
                    <wa-button variant="brand" appearance="filled" size="xs" type="submit" ${state.savingStoredConfig ? 'loading' : ''} ${busy || !interfaceOptions.length ? 'disabled' : ''}>
                        Save
                    </wa-button>
                    <wa-button appearance="plain" size="xs" type="button" data-new-stored-config ${busy ? 'disabled' : ''}>
                        ${selected ? 'Cancel' : 'Clear'}
                    </wa-button>
                </div>
            </form>
        </section>
    `;
}

export function renderIdentitiesModule({interfaceOptions, state}) {
    return `
        <section class="wa-stack wa-gap-m">
            ${renderModuleTopbar('Identities')}

            <div class="single-panel-layout single-panel-layout--wide wa-stack wa-gap-s">
                ${state.adoptionsError ? renderMessageBanner('Active identities', state.adoptionsError) : ''}
                ${state.interfaceSelectionError ? renderMessageBanner('Interfaces', state.interfaceSelectionError) : ''}
                ${state.storedConfigsError ? renderMessageBanner('Identities', state.storedConfigsError) : ''}
                ${state.storedConfigNotice ? renderMessageBanner('Identities', state.storedConfigNotice, 'success') : ''}

                <section class="config-management-layout wa-stack wa-gap-l">
                    ${renderStoredConfigEditor(interfaceOptions, state)}

                    <section class="stored-identity-library wa-stack wa-gap-xs">
                        <header class="section-heading wa-split wa-gap-xs"><h2 class="wa-heading-m">All identities</h2></header>
                        ${renderStoredConfigList(state)}
                    </section>
                </section>
            </div>
        </section>
    `;
}
