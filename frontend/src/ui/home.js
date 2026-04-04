import {escapeHTML, pill, renderMessageBanner} from './common';

export function renderModuleHome({logo, moduleLocalNetwork, state}) {
    const detectedCount = state.snapshot?.interfaces?.length;
    const availabilityText = detectedCount
        ? `${detectedCount} interfaces detected`
        : 'Inspect host interfaces';

    const adoptedCards = state.adoptedItems.map((item) => `
        <button class="module-card module-card--adopted panel" type="button" data-open-adopted-ip="${escapeHTML(item.ip)}">
            <div class="module-card__title-row">
                <div>
                    <span class="eyebrow">Adopted IP</span>
                    <h2>${escapeHTML(item.label || item.ip)}</h2>
                </div>
                ${pill('Open', 'success')}
            </div>
            <div class="module-card__meta">
                <span>${escapeHTML(item.interfaceName)}</span>
                <code>${escapeHTML(item.ip)}</code>
                <code>${escapeHTML(item.mac)}</code>
            </div>
        </button>
    `).join('');

    return `
        <main class="module-home">
            <header class="module-home__header">
                <img src="${logo}" alt="Kraken logo" class="module-home__mark" />
                <div>
                    <span class="eyebrow">Kraken</span>
                    <h1>Modules</h1>
                </div>
            </header>

            <div class="home-stack">
                ${[
                    state.adoptionsError ? renderMessageBanner('Adoption notice', state.adoptionsError) : '',
                    state.interfaceError && !state.snapshot ? renderMessageBanner('Interface notice', state.interfaceError) : '',
                ].join('')}

                <section class="module-card-grid module-card-grid--home">
                    <button class="module-card panel" type="button" data-open-module="${moduleLocalNetwork}">
                        <div class="module-card__title-row">
                            <div>
                                <span class="eyebrow">Module</span>
                                <h2>Local Network Settings</h2>
                                <p>${availabilityText}</p>
                            </div>
                            ${pill('Open', 'info')}
                        </div>
                        <div class="module-card__footer">
                            <span class="module-card__action">Enter</span>
                        </div>
                    </button>

                    <button class="module-card module-card--adopt panel" type="button" data-open-adopt-form>
                        <span class="module-card__plus">+</span>
                        <h2>(adopt IP)</h2>
                    </button>

                    ${adoptedCards}
                </section>
            </div>
        </main>
    `;
}
