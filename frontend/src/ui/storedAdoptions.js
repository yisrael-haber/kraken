import {
    renderIdentityFields,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {renderStoredConfigList} from './storedConfigCards';

function renderStoredConfigEditor(interfaceOptions, state) {
    const selected = Boolean(state.selectedStoredConfigLabel);
    const busy = state.savingStoredConfig || state.copyingStoredConfig || state.deletingStoredConfigLabel || state.adoptingStoredLabel;
    const selectOptions = renderInterfaceOptions(
        interfaceOptions,
        state.storedConfigEditor.interfaceName,
        'No adoptable interfaces available',
    );

    return `
        <section class="stored-identity-editor">
            <form id="stored-adoption-config-form" class="stored-identity-form">
                <div class="stored-identity-fields">
                    ${renderIdentityFields({
                        disabled: busy,
                        disabledFields: selected ? ['label'] : [],
                        form: state.storedConfigEditor,
                        interfaceOptions: selectOptions,
                        dataAttribute: 'data-stored-config-field',
                        fieldClassPrefix: 'stored-identity-field',
                        order: ['label', 'ip', 'subnetPrefix', 'interfaceName', 'defaultGateway', 'mac', 'mtu'],
                    })}
                </div>

                <div class="stored-identity-actions">
                    <button class="adopt-submit" type="submit" ${busy || !interfaceOptions.length ? 'disabled' : ''}>
                        ${state.savingStoredConfig ? 'Saving...' : 'Save'}
                    </button>
                    <button class="adopt-cancel" type="button" data-new-stored-config ${busy ? 'disabled' : ''}>
                        Reset
                    </button>
                </div>
            </form>
        </section>
    `;
}

export function renderStoredAdoptionsModule({interfaceOptions, state}) {
    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Saved Identities')}

            <main class="single-panel-layout single-panel-layout--wide">
                ${state.storedConfigsError ? renderMessageBanner('Saved identities', state.storedConfigsError) : ''}
                ${state.storedConfigNotice ? renderMessageBanner('Saved', state.storedConfigNotice) : ''}

                <section class="config-management-layout">
                    ${renderStoredConfigEditor(interfaceOptions, state)}

                    <section class="stored-identity-library">
                        ${renderStoredConfigList(state, 'manager')}
                    </section>
                </section>
            </main>
        </div>
    `;
}
