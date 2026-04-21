import {SCRIPT_SURFACE_TRANSPORT} from '../scriptModel';
import {renderScriptOptions, renderSurfaceScriptStatus} from './adoption';
import {
    escapeHTML,
    pill,
    renderCompactMetaLine,
    renderMessageBanner,
    renderModuleTopbar,
} from './common';

function renderStoredRouteActions(item, state) {
    if (state.pendingDeleteStoredRoute === item.label) {
        return `
            <div class="section-actions section-actions--confirm">
                <span class="inline-confirm">Delete this route?</span>
                <button
                    class="danger-button"
                    type="button"
                    data-confirm-delete-stored-route="${escapeHTML(item.label)}"
                    ${state.deletingStoredRouteLabel ? 'disabled' : ''}
                >
                    ${state.deletingStoredRouteLabel === item.label ? 'Deleting...' : 'Delete'}
                </button>
                <button
                    class="ghost-button"
                    type="button"
                    data-cancel-delete-stored-route
                    ${state.deletingStoredRouteLabel ? 'disabled' : ''}
                >
                    Cancel
                </button>
            </div>
        `;
    }

    const busy = state.deletingStoredRouteLabel || state.savingStoredRoute;
    return `
        <div class="section-actions stored-config-card__actions">
            <button
                class="ghost-button"
                type="button"
                data-edit-stored-route="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
            >
                Edit
            </button>
            <button
                class="ghost-button"
                type="button"
                data-stage-delete-stored-route="${escapeHTML(item.label)}"
                ${busy ? 'disabled' : ''}
            >
                Remove
            </button>
        </div>
    `;
}

function renderStoredRouteList(state) {
    if (state.storedRoutesLoading && !state.storedRoutes.length) {
        return '<div class="empty-state">Loading routes.</div>';
    }
    if (!state.storedRoutes.length) {
        return '<div class="empty-state">No routes.</div>';
    }

    return `
        <div class="config-card-list config-card-list--compact">
            ${state.storedRoutes.map((item) => `
                <article class="panel compact-list-card stored-config-card ${state.selectedStoredRouteLabel === item.label ? 'is-selected' : ''}">
                    <div class="stored-config-card__header">
                        <strong>${escapeHTML(item.label)}</strong>
                        ${pill(item.destinationCIDR, 'info')}
                    </div>
                    ${renderCompactMetaLine([
        {label: 'Via', value: item.viaAdoptedIP, code: true},
        {label: 'Transport', value: item.transportScriptName || 'None', code: Boolean(item.transportScriptName)},
    ])}
                    ${renderStoredRouteActions(item, state)}
                </article>
            `).join('')}
        </div>
    `;
}

function renderAdoptedReference(state) {
    if (!state.adoptedItems.length) {
        return '<small class="field-note">No adopted IPs active. Routes still save, but forward only when the selected via IP is adopted.</small>';
    }

    return `
        <small class="field-note">
            Active via IPs:
            ${state.adoptedItems.map((item) => `${escapeHTML(item.label || item.ip)} (<code>${escapeHTML(item.ip)}</code>)`).join(', ')}
        </small>
    `;
}

function renderStoredRouteEditor(state) {
    const busy = state.savingStoredRoute || state.deletingStoredRouteLabel || state.storedRoutesLoading;
    const isEditing = Boolean(state.selectedStoredRouteLabel);
    const selectedTransportScriptName = String(state.storedRouteEditor.transportScriptName || '');
    const transportScriptStatus = renderSurfaceScriptStatus(state.storedScripts, selectedTransportScriptName, SCRIPT_SURFACE_TRANSPORT);

    return `
        <section class="panel section-panel section-panel--compact form-panel">
            <div class="section-heading section-heading--tight">
                <div>
                    <h3>${isEditing ? escapeHTML(state.selectedStoredRouteLabel) : 'New route'}</h3>
                </div>
                <button class="ghost-button" type="button" data-new-stored-route ${busy ? 'disabled' : ''}>
                    New
                </button>
            </div>

            <form id="stored-route-form" class="form-stack form-stack--compact">
                <div class="compact-form-grid">
                    <label class="form-field">
                        <span>Label</span>
                        <input
                            type="text"
                            name="label"
                            value="${escapeHTML(state.storedRouteEditor.label)}"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-route-field="label"
                            ${(busy || isEditing) ? 'disabled' : ''}
                        />
                        <small class="field-note">Stable name.</small>
                    </label>

                    <label class="form-field">
                        <span>Destination CIDR</span>
                        <input
                            type="text"
                            name="destinationCIDR"
                            value="${escapeHTML(state.storedRouteEditor.destinationCIDR)}"
                            placeholder="10.0.0.0/24"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-route-field="destinationCIDR"
                            ${busy ? 'disabled' : ''}
                        />
                        <small class="field-note">Longest prefix wins.</small>
                    </label>

                    <label class="form-field">
                        <span>Via adopted IP</span>
                        <input
                            type="text"
                            name="viaAdoptedIP"
                            value="${escapeHTML(state.storedRouteEditor.viaAdoptedIP)}"
                            placeholder="192.168.56.10"
                            autocomplete="off"
                            spellcheck="false"
                            data-stored-route-field="viaAdoptedIP"
                            ${busy ? 'disabled' : ''}
                        />
                        ${renderAdoptedReference(state)}
                    </label>

                    <label class="form-field">
                        <span>Transport script</span>
                        <select
                            name="transportScriptName"
                            data-stored-route-field="transportScriptName"
                            ${busy || state.storedScriptsLoading ? 'disabled' : ''}
                        >
                            ${renderScriptOptions(state.storedScripts, SCRIPT_SURFACE_TRANSPORT, selectedTransportScriptName)}
                        </select>
                        <small class="field-note">Optional packet hook before egress.</small>
                    </label>
                </div>

                ${transportScriptStatus ? `<p class="field-note">${escapeHTML(transportScriptStatus)}</p>` : ''}

                <div class="form-actions form-actions--compact">
                    <button class="primary-button" type="submit" ${busy ? 'disabled' : ''}>
                        ${state.savingStoredRoute ? 'Saving...' : 'Save'}
                    </button>
                    <button class="ghost-button" type="button" data-new-stored-route ${busy ? 'disabled' : ''}>
                        Reset
                    </button>
                </div>
            </form>
        </section>
    `;
}

export function renderRoutingModule({state}) {
    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('')}

            <main class="single-panel-layout single-panel-layout--wide">
                ${state.storedRoutesError ? renderMessageBanner('Routes', state.storedRoutesError) : ''}
                ${state.storedRouteNotice ? renderMessageBanner('Saved', state.storedRouteNotice) : ''}
                ${state.storedScriptsError ? renderMessageBanner('Scripts', state.storedScriptsError) : ''}

                <section class="override-layout config-management-layout">
                    <section class="panel section-panel section-panel--compact">
                        <div class="section-heading section-heading--tight">
                            <h3>Routes</h3>
                        </div>

                        ${renderStoredRouteList(state)}
                    </section>

                    ${renderStoredRouteEditor(state)}
                </section>
            </main>
        </div>
    `;
}
