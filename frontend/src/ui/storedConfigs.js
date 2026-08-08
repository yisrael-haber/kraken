import {escapeHTML, pill} from './common';

function identityKey(label, ip) {
    return `${String(label)}\u0000${String(ip)}`;
}

function inventoryFor(state) {
    const configsByIdentity = new Map(state.storedConfigs.map((config) => [
        identityKey(config.label, config.ip),
        config,
    ]));
    const usedConfigs = new Set();
    const activeIPs = new Set(state.adoptedItems.map((item) => String(item.ip)));
    const active = state.adoptedItems.map((item) => {
        const config = configsByIdentity.get(identityKey(item.label, item.ip)) || null;
        if (config) {
            usedConfigs.add(config);
        }
        return {active: item, config, conflict: false};
    }).sort(compareInventoryItems);
    const inactive = state.storedConfigs
        .filter((config) => !usedConfigs.has(config))
        .map((config) => ({
            active: null,
            config,
            conflict: activeIPs.has(String(config.ip)),
        }))
        .sort(compareInventoryItems);
    return [...active, ...inactive];
}

function compareInventoryItems(left, right) {
    const leftItem = left.config || left.active;
    const rightItem = right.config || right.active;
    return String(leftItem.label || leftItem.ip).localeCompare(String(rightItem.label || rightItem.ip), undefined, {
        sensitivity: 'base',
    });
}

function renderIdentityMeta(record) {
    const item = record.config || record.active;
    const interfaceName = record.config?.interfaceName || record.active?.interface?.Name || '';
    return `
        <div class="stored-identity-meta wa-cluster wa-gap-xs wa-caption-xs">
            <code>${escapeHTML(item.ip)}/${escapeHTML(item.subnetPrefix || 24)}</code>
            ${interfaceName ? `<span>${escapeHTML(interfaceName)}</span>` : ''}
            ${record.conflict ? pill('IP in use', 'warn') : ''}
        </div>
    `;
}

function renderCopyForm(item, state) {
    return `
        <form id="stored-config-copy-form" class="library-row__actions wa-cluster wa-gap-2xs">
            <wa-input
                class="stored-identity-copy-input"
                type="text"
                name="label"
                value="${escapeHTML(state.storedConfigCopyLabel)}"
                placeholder="Copy as"
                aria-label="New identity label"
                autocomplete="off"
                spellcheck="false"
                data-stored-config-copy-label
                autofocus
                appearance="filled"
                size="xs"
                ${state.copyingStoredConfig ? 'disabled' : ''}
            ></wa-input>
            <wa-button variant="brand" appearance="filled" size="xs" type="submit" ${state.copyingStoredConfig ? 'loading disabled' : ''}>
                Create copy
            </wa-button>
            <wa-button appearance="plain" size="xs" type="button" data-cancel-copy-stored-config ${state.copyingStoredConfig ? 'disabled' : ''}>
                Cancel
            </wa-button>
        </form>
    `;
}

function renderDeleteConfirmation(item, state) {
    return `
        <div class="library-row__actions inline-confirmation wa-cluster wa-gap-2xs">
            <span class="inline-confirm wa-caption-xs">
                Delete saved configuration?
            </span>
            <wa-button
                variant="danger"
                appearance="plain"
                size="xs"
                type="button"
                data-confirm-delete-stored-config="${escapeHTML(item.label)}"
                ${state.deletingStoredConfigLabel === item.label ? 'loading' : ''}
                ${state.deletingStoredConfigLabel ? 'disabled' : ''}
            >Delete</wa-button>
            <wa-button appearance="plain" size="xs" type="button" data-cancel-delete-stored-config ${state.deletingStoredConfigLabel ? 'disabled' : ''}>
                Cancel
            </wa-button>
        </div>
    `;
}

function renderConfigurationActions(record, state) {
    const item = record.config;
    if (!item) {
        return '';
    }
    if (state.pendingCopyStoredConfig === item.label) {
        return renderCopyForm(item, state);
    }
    if (state.pendingDeleteStoredConfig === item.label) {
        return renderDeleteConfirmation(item, state);
    }

    const busy = state.adoptingStoredLabel || state.copyingStoredConfig
        || state.deletingStoredConfigLabel || state.savingStoredConfig || state.releasingAdoption;
    return `
        <div class="identity-row-actions library-row__actions wa-cluster wa-gap-2xs">
        ${record.active ? `
            <wa-button appearance="filled" size="xs" type="button" data-release-adoption="${escapeHTML(record.active.ip)}" ${state.releasingAdoption === record.active.ip ? 'loading' : ''} ${busy && state.releasingAdoption !== record.active.ip ? 'disabled' : ''} title="Stop identity">
                <wa-icon library="kraken" name="stop" label="Stop ${escapeHTML(item.label)}"></wa-icon>
            </wa-button>
        ` : `
            <wa-button
                variant="brand"
                appearance="filled"
                size="xs"
                type="button"
                data-adopt-stored-config="${escapeHTML(item.label)}"
                ${state.adoptingStoredLabel === item.label ? 'loading' : ''}
                ${busy || record.conflict ? 'disabled' : ''}
                title="${record.conflict ? 'This IP is active under another label' : 'Adopt identity'}"
            ><wa-icon library="kraken" name="play" label="Adopt ${escapeHTML(item.label)}"></wa-icon></wa-button>
        `}
        <wa-button appearance="plain" size="xs" type="button" data-edit-stored-config="${escapeHTML(item.label)}" ${busy ? 'disabled' : ''} title="Edit identity">
            <wa-icon library="kraken" name="pencil" label="Edit ${escapeHTML(item.label)}"></wa-icon>
        </wa-button>
        <wa-button appearance="plain" size="xs" type="button" data-stage-copy-stored-config="${escapeHTML(item.label)}" ${busy ? 'disabled' : ''} title="Copy identity">
            <wa-icon library="kraken" name="copy" label="Copy ${escapeHTML(item.label)}"></wa-icon>
        </wa-button>
        ${record.active ? '' : `
            <wa-button appearance="plain" size="xs" type="button" data-stage-delete-stored-config="${escapeHTML(item.label)}" ${busy ? 'disabled' : ''} title="Delete saved configuration">
                <wa-icon library="kraken" name="xmark" label="Delete saved configuration for ${escapeHTML(item.label)}"></wa-icon>
            </wa-button>
        `}
        </div>
    `;
}

function renderActiveOnlyActions(record, state) {
    const busy = Boolean(state.releasingAdoption);
    return `
        <div class="identity-row-actions library-row__actions wa-cluster wa-gap-2xs">
            <wa-button appearance="filled" size="xs" type="button" data-release-adoption="${escapeHTML(record.active.ip)}" ${state.releasingAdoption === record.active.ip ? 'loading' : ''} ${busy && state.releasingAdoption !== record.active.ip ? 'disabled' : ''} title="Stop identity">
                <wa-icon library="kraken" name="stop" label="Stop ${escapeHTML(record.active.label || record.active.ip)}"></wa-icon>
            </wa-button>
        </div>
    `;
}

function renderInventoryRow(record, state) {
    const item = record.config || record.active;
    const label = item.label || item.ip;
    const selected = record.config && state.selectedStoredConfigLabel === record.config.label;
    return `
        <article class="library-row stored-identity-row ${selected ? 'is-selected' : ''}">
            ${record.active ? `
                <div class="wa-stack wa-gap-2xs wa-align-items-start">
                    <h3 class="wa-heading-s wa-text-truncate">
                        <wa-button class="identity-name-action" appearance="plain" size="xs" type="button" data-open-adopted-ip="${escapeHTML(record.active.ip)}">
                            ${escapeHTML(label)}
                        </wa-button>
                    </h3>
                    ${renderIdentityMeta(record)}
                </div>
            ` : `
                <div class="wa-stack wa-gap-2xs wa-align-items-start">
                    <h3 class="wa-heading-s wa-text-truncate">${escapeHTML(label)}</h3>
                    ${renderIdentityMeta(record)}
                </div>
            `}
            ${record.active && !record.config
                ? renderActiveOnlyActions(record, state)
                : renderConfigurationActions(record, state)}
        </article>
    `;
}

function renderStoredConfigList(state) {
    const inventory = inventoryFor(state);
    if (state.storedConfigsLoading && !inventory.length) {
        return '<div class="empty-state wa-caption-s">Loading identities.</div>';
    }
    if (!inventory.length) {
        return '<div class="empty-state wa-caption-s">No identities yet.</div>';
    }
    return inventory.map((record) => renderInventoryRow(record, state)).join('');
}

export {renderStoredConfigList};
