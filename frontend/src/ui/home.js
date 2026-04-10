import {escapeHTML, pill, renderMessageBanner} from './common';

function renderSummaryGrid(rows) {
    return `
        <dl class="summary-grid">
            ${rows.map((row) => `
                <div class="summary-grid__row">
                    <dt>${escapeHTML(row.label)}</dt>
                    <dd>${row.code ? `<code>${escapeHTML(row.value)}</code>` : escapeHTML(row.value)}</dd>
                </div>
            `).join('')}
        </dl>
    `;
}

export function renderModuleHome({logo, moduleStoredAdoptions, moduleScripts, state}) {
    const adoptedCards = state.adoptedItems.length
        ? state.adoptedItems.map((item) => `
            <article
                class="home-item-card panel"
                ${state.pendingDeleteAdoption === item.ip ? '' : `data-open-adopted-ip="${escapeHTML(item.ip)}"`}
                role="button"
                tabindex="0"
                aria-label="Open adopted IP ${escapeHTML(item.label || item.ip)}"
            >
                <div class="home-item-card__row">
                    <strong>${escapeHTML(item.label || item.ip)}</strong>
                    ${pill('Active', 'success')}
                </div>
                ${renderSummaryGrid([
        {label: 'Iface', value: item.interfaceName},
        {label: 'IP', value: item.ip, code: true},
        ...(item.defaultGateway ? [{label: 'Gateway', value: item.defaultGateway, code: true}] : []),
        {label: 'MAC', value: item.mac, code: true},
    ])}
                ${state.pendingDeleteAdoption === item.ip ? `
                    <div class="home-item-card__confirm">
                        <span class="inline-confirm">Remove this adoption?</span>
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
                    <div class="home-item-card__actions home-item-card__actions--single">
                        <button
                            class="ghost-button"
                            type="button"
                            data-stage-delete-adoption="${escapeHTML(item.ip)}"
                            ${state.deletingAdoption ? 'disabled' : ''}
                        >
                            Unadopt
                        </button>
                    </div>
                `}
            </article>
        `).join('')
        : '<div class="empty-state">No adopted IPs yet.</div>';

    let configDirectoryBody = '<p class="home-config-footer__message">Resolving configuration directory...</p>';
    if (state.configurationDirectoryError) {
        configDirectoryBody = `<p class="home-config-footer__message home-config-footer__message--error">${escapeHTML(state.configurationDirectoryError)}</p>`;
    } else if (state.configurationDirectory) {
        configDirectoryBody = `
            <div class="home-config-footer__path-row">
                <span>Configuration directory</span>
                <code>${escapeHTML(state.configurationDirectory)}</code>
            </div>
        `;
    }

    return `
        <main class="module-home">
            <header class="module-home__header">
                <img src="${logo}" alt="Kraken logo" class="module-home__mark" />
                <div>
                    <span class="eyebrow">Kraken</span>
                    <h1>Workspace</h1>
                </div>
            </header>

            <div class="home-stack">
                ${[
                    state.adoptionsError ? renderMessageBanner('Adoption notice', state.adoptionsError) : '',
                    state.interfaceSelectionError && !state.interfaceSelection ? renderMessageBanner('Interface notice', state.interfaceSelectionError) : '',
                ].join('')}

                <section class="home-columns">
                    <div class="home-column">
                        <header class="home-column__header">
                            <div class="home-column__copy">
                                <span class="eyebrow">Adopted</span>
                                <h2>Adopted IPs</h2>
                                <p>${state.adoptedItems.length ? `${state.adoptedItems.length} active` : 'Ready for a new identity'}</p>
                            </div>
                        </header>
                        <div class="home-column__body">
                            ${adoptedCards}
                            <div class="home-column__footer">
                                <button
                                    class="ghost-button home-column__plus-button"
                                    type="button"
                                    data-open-adopt-form
                                    aria-label="Adopt IP"
                                    title="Adopt IP"
                                >
                                    +
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="home-column">
                        <header class="home-column__header">
                            <div class="home-column__copy">
                                <span class="eyebrow">Kraken</span>
                                <h2>Kraken Configurations</h2>
                                <p>Persistent identities and dynamic packet scripts.</p>
                            </div>
                        </header>
                        <div class="home-column__body">
                            <button class="home-item-card panel" type="button" data-open-module="${moduleStoredAdoptions}">
                                <div class="home-item-card__row">
                                    <strong>Stored adoptions</strong>
                                    ${pill('Open', 'info')}
                                </div>
                                <p>Create, edit, adopt, and remove stored identities.</p>
                            </button>
                            <button class="home-item-card panel" type="button" data-open-module="${moduleScripts}">
                                <div class="home-item-card__row">
                                    <strong>Starlark scripts</strong>
                                    ${pill('Open', 'info')}
                                </div>
                                <p>Filesystem-backed packet editing and mutation scripts written in Starlark.</p>
                            </button>
                        </div>
                    </div>
                </section>
            </div>

            <footer class="panel module-home__footer home-config-footer">
                <div class="home-config-footer__copy">
                    <span class="eyebrow">Config</span>
                    <strong>Default filesystem location</strong>
                </div>
                ${configDirectoryBody}
            </footer>
        </main>
    `;
}
