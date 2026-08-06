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
        <section class="stored-identity-editor">
            <header class="section-heading"><h3>${selected ? 'Edit identity' : 'New identity'}</h3></header>
            <form id="stored-adoption-config-form" class="identity-editor-form">
                ${renderIdentityFields({
                    disabled: busy,
                    disabledFields: selected ? ['label'] : [],
                    form: state.storedConfigEditor,
                    interfaceOptions: selectOptions,
                    dataAttribute: 'data-stored-config-field',
                    order: ['label', 'ip', 'subnetPrefix', 'interfaceName', 'defaultGateway', 'mac', 'mtu'],
                })}

                <div class="form-actions">
                    <wa-button variant="brand" appearance="outlined" size="xs" type="submit" ${state.savingStoredConfig ? 'loading' : ''} ${busy || !interfaceOptions.length ? 'disabled' : ''}>
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

export function renderStoredAdoptionsModule({interfaceOptions, state}) {
    return `
        <div class="module-frame">
            ${renderModuleTopbar('Saved Identities')}

            <main class="single-panel-layout single-panel-layout--wide">
                ${state.storedConfigsError ? renderMessageBanner('Saved identities', state.storedConfigsError) : ''}
                ${state.storedConfigNotice ? renderMessageBanner('Saved', state.storedConfigNotice, 'success') : ''}

                <section class="config-management-layout">
                    ${renderStoredConfigEditor(interfaceOptions, state)}

                    <section class="stored-identity-library">
                        <header class="section-heading"><h3>Saved</h3></header>
                        ${renderStoredConfigList(state)}
                    </section>
                </section>
            </main>
        </div>
    `;
}
