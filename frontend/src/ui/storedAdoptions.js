import {
    escapeHTML,
    renderInterfaceOptions,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';
import {renderStoredConfigList} from './storedConfigCards';

function renderStoredConfigEditor(interfaceOptions, state) {
    const busy = state.savingStoredConfig || state.deletingStoredConfigLabel || state.adoptingStoredLabel;
    const selectOptions = renderInterfaceOptions(
        interfaceOptions,
        state.storedConfigEditor.interfaceName,
        'No adoptable interfaces available',
    );

    return `
        <section class="stored-identity-editor">
            <form id="stored-adoption-config-form" class="stored-identity-form">
                <div class="stored-identity-fields">
                    <label class="adopt-control stored-identity-field--label">
                        <span>Label</span>
                        <input
                            type="text"
                            name="label"
                            value="${escapeHTML(state.storedConfigEditor.label)}"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="label"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

                    <label class="adopt-control stored-identity-field--ip">
                        <span>IP</span>
                        <input
                            type="text"
                            name="ip"
                            value="${escapeHTML(state.storedConfigEditor.ip)}"
                            placeholder="192.168.56.50"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="ip"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

                    <label class="adopt-control stored-identity-field--prefix">
                        <span>Prefix</span>
                        <input
                            type="text"
                            name="subnetPrefix"
                            value="${escapeHTML(state.storedConfigEditor.subnetPrefix || '')}"
                            placeholder="24"
                            autocomplete="off"
                            spellcheck="false"
                            inputmode="numeric"
                            data-stored-config-field="subnetPrefix"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

                    <label class="adopt-control stored-identity-field--interface">
                        <span>Interface</span>
                        <select
                            name="interfaceName"
                            data-stored-config-field="interfaceName"
                            ${busy ? 'disabled' : ''}
                        >
                            ${selectOptions}
                        </select>
                    </label>

                    <label class="adopt-control stored-identity-field--gateway">
                        <span>Gateway</span>
                        <input
                            type="text"
                            name="defaultGateway"
                            value="${escapeHTML(state.storedConfigEditor.defaultGateway || '')}"
                            placeholder="Optional"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="defaultGateway"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

                    <label class="adopt-control stored-identity-field--mac">
                        <span>MAC</span>
                        <input
                            type="text"
                            name="mac"
                            value="${escapeHTML(state.storedConfigEditor.mac)}"
                            placeholder="Optional"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-config-field="mac"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

                    <label class="adopt-control stored-identity-field--mtu">
                        <span>MTU</span>
                        <input
                            type="text"
                            name="mtu"
                            value="${escapeHTML(state.storedConfigEditor.mtu || '')}"
                            placeholder="Iface"
                            autocomplete="off"
                            spellcheck="false"
                            inputmode="numeric"
                            data-stored-config-field="mtu"
                            ${busy ? 'disabled' : ''}
                        />
                    </label>

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
