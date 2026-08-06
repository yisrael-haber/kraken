import {escapeHTML, renderMessageBanner} from './common';
import {
    MODULE_GLOBAL_SCRIPTING,
    MODULE_KEYTAB,
    MODULE_OPERATIONS,
    MODULE_SERVICES,
    MODULE_STORED_ADOPTIONS,
    MODULE_TRANSPORT_SCRIPTS,
} from '../app/state';

const HOME_ACTIONS = [
    ['Saved identities', MODULE_STORED_ADOPTIONS],
    ['Transport scripts', MODULE_TRANSPORT_SCRIPTS],
    ['Global scripting', MODULE_GLOBAL_SCRIPTING],
    ['Operations', MODULE_OPERATIONS],
    ['Services', MODULE_SERVICES],
    ['Keytab builder', MODULE_KEYTAB],
];

export function renderModuleHome({logo, state}) {
    const adoptedCards = state.adoptedItems.length
        ? state.adoptedItems.map((item) => {
            const hasDistinctLabel = item.label && item.label !== item.ip;
            return `
            <div class="home-adopted-item">
                ${state.pendingDeleteAdoption === item.ip ? `
                    <div class="adopted-identity-title adopted-identity-title--home">
                        <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                        ${hasDistinctLabel ? `<code>${escapeHTML(item.ip)}</code>` : ''}
                    </div>
                    <div class="inline-confirmation">
                        <span class="inline-confirm">Remove this identity?</span>
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
                        <div class="adopted-identity-title adopted-identity-title--home">
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
        : '<p class="home-empty">No identities are currently adopted.</p>';

    let configDirectoryBody = '<span class="home-config-footer__message">Resolving path.</span>';
    if (state.configurationDirectoryError) {
        configDirectoryBody = `<span class="home-config-footer__message home-config-footer__message--error">${escapeHTML(state.configurationDirectoryError)}</span>`;
    } else if (state.configurationDirectory) {
        configDirectoryBody = `<code>${escapeHTML(state.configurationDirectory)}</code>`;
    }

    return `
        <main class="module-home">
            <header class="module-home__header">
                <img src="${logo}" alt="Kraken logo" class="module-home__mark" />
                <h1>Kraken</h1>
            </header>

            <div class="home-stack">
                ${[
                    state.adoptionsError ? renderMessageBanner('Adoption', state.adoptionsError) : '',
                    state.interfaceSelectionError && !state.interfaceSelection ? renderMessageBanner('Interfaces', state.interfaceSelectionError) : '',
                ].join('')}

                <section class="home-content">
                    <wa-card class="home-card" appearance="outlined" with-header>
                        <h2 slot="header">Adopted identities</h2>
                        <div class="home-adopted-list">
                            ${adoptedCards}
                        </div>
                    </wa-card>

                    <wa-card class="home-card" appearance="outlined" with-header>
                        <h2 slot="header">Tools</h2>
                        <nav class="home-tool-grid" aria-label="Kraken tools">
                            ${HOME_ACTIONS.map(([label, module]) => `
                                <wa-button appearance="filled" size="xs" type="button" data-open-module="${escapeHTML(module)}">
                                    ${escapeHTML(label)}
                                </wa-button>
                            `).join('')}
                        </nav>
                    </wa-card>
                </section>
            </div>

            <footer class="module-home__footer home-config-footer">
                <span class="home-config-footer__label">Config</span>
                ${configDirectoryBody}
            </footer>
        </main>
    `;
}
