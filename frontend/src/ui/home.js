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
    ['Network', [
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
            <div class="home-adopted-item wa-flank:end wa-gap-2xs">
                ${state.pendingDeleteAdoption === item.ip ? `
                    <div class="home-adopted-confirm-copy wa-stack wa-gap-3xs">
                        <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                        <span class="wa-caption-xs">Remove this identity?</span>
                    </div>
                    <div class="home-adopted-confirmation inline-confirmation wa-cluster wa-gap-2xs">
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
                        size="m"
                        type="button"
                        data-open-adopted-ip="${escapeHTML(item.ip)}"
                        aria-label="Open adopted IP ${escapeHTML(item.label || item.ip)}"
                    >
                        <wa-icon class="home-status-glyph" slot="start" library="system" name="circle"></wa-icon>
                        <span class="home-adopted-summary wa-stack wa-gap-3xs">
                            <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                            ${hasDistinctLabel ? `<code class="home-adopted-meta">${escapeHTML(item.ip)}</code>` : ''}
                        </span>
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
        : `
            <div class="home-adopted-empty wa-cluster">
                <span>No active identities</span>
            </div>
        `;

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
        <wa-page class="home-page">
            <header slot="main-header" class="home-header">
                <div class="home-shell">
                    <div class="home-brand wa-cluster wa-gap-s">
                        <img src="${logo}" alt="" class="module-home__mark" />
                        <h1>Kraken</h1>
                    </div>
                </div>
            </header>

            <main>
                <div class="home-shell wa-stack wa-gap-2xl">
                    ${messages ? `<div class="wa-stack wa-gap-s">${messages}</div>` : ''}

                    <section class="home-identity-workspace wa-stack wa-gap-m" aria-labelledby="home-identities-heading">
                        <div class="home-section-heading wa-split wa-gap-m wa-align-items-baseline">
                            <h2 id="home-identities-heading">Identities</h2>
                            <wa-button class="home-library-action" appearance="plain" size="s" type="button" data-open-module="${MODULE_STORED_ADOPTIONS}">
                                <wa-icon slot="start" library="system" name="user"></wa-icon>
                                Saved identities
                                <wa-icon slot="end" library="system" name="chevron-right"></wa-icon>
                            </wa-button>
                        </div>
                        <div class="home-adopted-list">
                            ${adoptedCards}
                        </div>
                    </section>

                    <section class="home-workspace wa-stack wa-gap-m" aria-labelledby="home-tools-heading">
                        <h2 id="home-tools-heading">Tools</h2>
                        <nav class="home-tool-grid wa-grid wa-gap-m" aria-label="Kraken workspace">
                            ${HOME_TOOL_GROUPS.map(([group, actions], groupIndex) => `
                                <section class="home-tool-group wa-stack wa-gap-xs" aria-labelledby="home-tool-group-${groupIndex}">
                                    <h3 id="home-tool-group-${groupIndex}" class="wa-caption-xs wa-text-uppercase">${escapeHTML(group)}</h3>
                                    <div class="home-tool-list wa-stack wa-gap-3xs">
                                        ${actions.map(([label, icon, module]) => `
                                            <wa-button class="home-tool" appearance="plain" size="m" type="button" data-open-module="${escapeHTML(module)}">
                                                <wa-icon class="home-tool__icon" slot="start" library="system" name="${icon}"></wa-icon>
                                                ${escapeHTML(label)}
                                                <wa-icon class="home-tool__chevron" slot="end" library="system" name="chevron-right"></wa-icon>
                                            </wa-button>
                                        `).join('')}
                                    </div>
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
