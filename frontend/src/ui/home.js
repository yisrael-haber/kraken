import {escapeHTML, renderMessageBanner} from './common';

export function renderModuleHome({logo, moduleStoredAdoptions, moduleScripts, state}) {
    const adoptedCards = state.adoptedItems.length
        ? state.adoptedItems.map((item) => {
            const hasDistinctLabel = item.label && item.label !== item.ip;
            return `
            <article
                class="home-item-card panel"
                ${state.pendingDeleteAdoption === item.ip ? '' : `data-open-adopted-ip="${escapeHTML(item.ip)}"`}
                role="button"
                tabindex="0"
                aria-label="Open adopted IP ${escapeHTML(item.label || item.ip)}"
            >
                ${state.pendingDeleteAdoption === item.ip ? `
                    <div class="home-adopted-row">
                        <div class="adopted-identity-title adopted-identity-title--home">
                            <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                            ${hasDistinctLabel ? `<code>${escapeHTML(item.ip)}</code>` : ''}
                        </div>
                    </div>
                    <div class="home-item-card__confirm">
                        <span class="inline-confirm">Remove this identity?</span>
                        <div class="home-item-card__actions">
                            <button
                                class="danger-button"
                                type="button"
                                data-confirm-delete-adoption="${escapeHTML(item.ip)}"
                                ${state.deletingAdoption ? 'disabled' : ''}
                            >
                                ${state.deletingAdoption ? 'Removing...' : 'Remove'}
                            </button>
                            <button
                                class="ghost-button"
                                type="button"
                                data-cancel-delete-adoption
                                ${state.deletingAdoption ? 'disabled' : ''}
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                ` : `
                    <div class="home-adopted-row">
                        <div class="adopted-identity-title adopted-identity-title--home">
                            <strong>${escapeHTML(hasDistinctLabel ? item.label : item.ip)}</strong>
                            ${hasDistinctLabel ? `<code>${escapeHTML(item.ip)}</code>` : ''}
                        </div>
                        <button
                            class="ghost-button home-trash-button"
                            type="button"
                            data-stage-delete-adoption="${escapeHTML(item.ip)}"
                            ${state.deletingAdoption ? 'disabled' : ''}
                            aria-label="Remove ${escapeHTML(item.label || item.ip)}"
                            title="Remove identity"
                        >
                            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3m3 0-1 13H7L6 7m4 4v5m4-5v5" /></svg>
                        </button>
                    </div>
                `}
            </article>
        `;
        }).join('')
        : '<div class="empty-state">No adopted identities.</div>';

    let configDirectoryBody = '<p class="home-config-footer__message">Resolving path.</p>';
    if (state.configurationDirectoryError) {
        configDirectoryBody = `<p class="home-config-footer__message home-config-footer__message--error">${escapeHTML(state.configurationDirectoryError)}</p>`;
    } else if (state.configurationDirectory) {
        configDirectoryBody = `
            <div class="home-config-footer__path-row">
                <span>Path</span>
                <code>${escapeHTML(state.configurationDirectory)}</code>
            </div>
        `;
    }

    return `
        <main class="module-home">
            <header class="module-home__header">
                <img src="${logo}" alt="Kraken logo" class="module-home__mark" />
                <div>
                    <h1>Kraken</h1>
                </div>
            </header>

            <div class="home-stack">
                ${[
                    state.adoptionsError ? renderMessageBanner('Adoption', state.adoptionsError) : '',
                    state.interfaceSelectionError && !state.interfaceSelection ? renderMessageBanner('Interfaces', state.interfaceSelectionError) : '',
                ].join('')}

                <section class="home-columns">
                    <div class="home-column">
                        <header class="home-column__header">
                            <h2>Adopted Identities</h2>
                        </header>
                        <div class="home-column__body">
                            ${adoptedCards}
                            <div class="home-column__footer">
                                <button
                                    class="ghost-button home-column__plus-button"
                                    type="button"
                                    data-open-adopt-form
                                    aria-label="Adopt identity"
                                    title="Adopt identity"
                                >
                                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="home-column">
                        <header class="home-column__header">
                            <h2>Workspace</h2>
                        </header>
                        <div class="home-column__body">
                            <button class="home-item-card panel" type="button" data-open-module="${moduleStoredAdoptions}">
                                <strong>Saved identities</strong>
                            </button>
                            <button class="home-item-card panel" type="button" data-open-module="${moduleScripts}">
                                <strong>Scripts</strong>
                            </button>
                        </div>
                    </div>
                </section>
            </div>

            <footer class="panel module-home__footer home-config-footer">
                <div class="home-config-footer__copy">
                    <strong>Config path</strong>
                </div>
                ${configDirectoryBody}
            </footer>
        </main>
    `;
}
