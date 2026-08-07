import {escapeHTML, renderMessageBanner} from './common';
import {
    MODULE_GLOBAL_SCRIPTING,
    MODULE_KEYTAB,
    MODULE_OPERATIONS,
    MODULE_SERVICES,
    MODULE_STORED_ADOPTIONS,
    MODULE_TRANSPORT_SCRIPTS,
} from '../app/state';

const HOME_TOOL_GROUPS = [
    ['Scripting', [
        ['Transport scripts', 'file-code', MODULE_TRANSPORT_SCRIPTS],
        ['Global scripting', 'play-circle', MODULE_GLOBAL_SCRIPTING],
    ]],
    ['Actions', [
        ['Operations', 'gauge', MODULE_OPERATIONS],
        ['Services', 'gear', MODULE_SERVICES],
    ]],
    ['Offline', [
        ['Keytab builder', 'file', MODULE_KEYTAB],
    ]],
];

export function renderModuleHome({logo, state}) {
    const messages = [
        state.adoptionsError ? renderMessageBanner('Adoption', state.adoptionsError) : '',
        state.interfaceSelectionError && !state.interfaceSelection ? renderMessageBanner('Interfaces', state.interfaceSelectionError) : '',
    ].filter(Boolean).join('');

    const adoptedCards = state.adoptedItems.length
        ? state.adoptedItems.map((item) => {
            const hasDistinctLabel = item.label && item.label !== item.ip;
            return `
            <div class="home-adopted-item wa-flank:end wa-gap-xs">
                ${state.pendingDeleteAdoption === item.ip ? `
                    <div class="adopted-identity-title wa-cluster wa-gap-2xs wa-align-items-baseline">
                        <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                        ${hasDistinctLabel ? `<code>${escapeHTML(item.ip)}</code>` : ''}
                    </div>
                    <div class="inline-confirmation wa-cluster wa-gap-2xs">
                        <span class="inline-confirm wa-caption-xs">Remove this identity?</span>
                        <wa-button
                            variant="danger"
                            appearance="plain"
                            size="xs"
                            type="button"
                            data-confirm-delete-adoption="${escapeHTML(item.ip)}"
                            ${state.deletingAdoption ? 'loading' : ''}
                            ${state.deletingAdoption ? 'disabled' : ''}
                        >
                            Remove
                        </wa-button>
                        <wa-button
                            appearance="plain"
                            size="xs"
                            type="button"
                            data-cancel-delete-adoption
                            ${state.deletingAdoption ? 'disabled' : ''}
                        >
                            Cancel
                        </wa-button>
                    </div>
                ` : `
                    <wa-button
                        class="home-adopted-open"
                        appearance="plain"
                        size="s"
                        type="button"
                        data-open-adopted-ip="${escapeHTML(item.ip)}"
                        aria-label="Open adopted IP ${escapeHTML(item.label || item.ip)}"
                    >
                        <div class="adopted-identity-title wa-cluster wa-gap-2xs wa-align-items-baseline">
                            <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                            ${hasDistinctLabel ? `<code>${escapeHTML(item.ip)}</code>` : ''}
                        </div>
                    </wa-button>
                    <wa-button
                        appearance="plain"
                        size="xs"
                        type="button"
                        data-stage-delete-adoption="${escapeHTML(item.ip)}"
                        ${state.deletingAdoption ? 'disabled' : ''}
                        title="Remove identity"
                    >
                        <wa-icon library="system" name="xmark" label="Remove ${escapeHTML(item.label || item.ip)}"></wa-icon>
                    </wa-button>
                `}
            </div>
        `;
        }).join('')
        : '<p class="wa-caption-s">No identities are currently adopted.</p>';

    let configDirectoryBody = '<span>Resolving path.</span>';
    if (state.configurationDirectoryError) {
        configDirectoryBody = `<span class="home-config-footer__message--error">${escapeHTML(state.configurationDirectoryError)}</span>`;
    } else if (state.configurationDirectory) {
        configDirectoryBody = `
            <code>${escapeHTML(state.configurationDirectory)}</code>
            <wa-copy-button value="${escapeHTML(state.configurationDirectory)}" copy-label="Copy config path" tooltip="copy"></wa-copy-button>
        `;
    }

    return `
        <wa-page>
            <header slot="main-header">
                <div class="home-shell wa-cluster wa-gap-xs">
                    <img src="${logo}" alt="" class="module-home__mark" />
                    <h1 class="wa-heading-l">Kraken</h1>
                </div>
            </header>

            <main>
                <div class="home-shell wa-stack wa-gap-3xl">
                    ${messages ? `<div class="wa-stack wa-gap-s">${messages}</div>` : ''}

                    <section class="home-identity-workspace wa-stack wa-gap-l" aria-labelledby="home-identities-heading">
                        <h2 id="home-identities-heading" class="wa-heading-m">Identities</h2>
                        <div class="wa-stack wa-gap-xs">
                            <h3 class="wa-caption-xs wa-text-uppercase">Library</h3>
                            <div class="wa-cluster">
                                <wa-button variant="neutral" appearance="filled" size="m" type="button" data-open-module="${MODULE_STORED_ADOPTIONS}">
                                    <wa-icon slot="start" library="system" name="user"></wa-icon>
                                    Saved identities
                                    <wa-icon slot="end" library="system" name="chevron-right"></wa-icon>
                                </wa-button>
                            </div>
                        </div>
                        <div class="wa-stack wa-gap-xs">
                            <h3 class="wa-caption-xs wa-text-uppercase">Adopted</h3>
                            <div>
                                ${adoptedCards}
                            </div>
                        </div>
                    </section>

                    <section class="wa-stack wa-gap-s" aria-labelledby="home-tools-heading">
                        <h2 id="home-tools-heading" class="wa-heading-m">Tools</h2>
                        <nav class="home-tool-grid wa-grid wa-gap-xl" aria-label="Kraken tools">
                            ${HOME_TOOL_GROUPS.map(([group, actions]) => `
                                <section class="wa-stack wa-gap-s">
                                    <h3 class="wa-caption-xs wa-text-uppercase">${escapeHTML(group)}</h3>
                                    ${actions.map(([label, icon, module]) => `
                                        <wa-button class="home-tool" appearance="plain" size="s" type="button" data-open-module="${escapeHTML(module)}">
                                            <wa-icon slot="start" library="system" name="${icon}"></wa-icon>
                                            ${escapeHTML(label)}
                                        </wa-button>
                                    `).join('')}
                                </section>
                            `).join('')}
                        </nav>
                    </section>
                </div>
            </main>

            <footer slot="main-footer" class="home-config-footer">
                <div class="home-shell wa-cluster wa-gap-xs wa-align-items-baseline">
                    <span class="wa-caption-2xs wa-text-uppercase">Config</span>
                    ${configDirectoryBody}
                </div>
            </footer>
        </wa-page>
    `;
}
