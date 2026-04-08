import {
    escapeHTML,
    interfaceBadges,
    previewAddresses,
    renderDataList,
    renderFlagList,
    renderInterfaceTags,
    renderMessageBanner,
    renderModuleTopbar,
    renderOverviewRows,
    renderStateLayout,
} from './common';

function renderSidebar({items, selected, state}) {
    let listMarkup = '<div class="empty-state">No interfaces match this filter.</div>';

    if (state.interfacesLoading && !state.snapshot?.interfaces?.length) {
        listMarkup = '<div class="empty-state">Loading interface inventory...</div>';
    } else if (items.length) {
        listMarkup = items.map((item) => {
            const selectedClass = selected && selected.name === item.name ? 'is-selected' : '';

            return `
                <button class="interface-item ${selectedClass}" type="button" data-interface="${escapeHTML(item.name)}">
                    <div class="interface-item__top">
                        <strong>${escapeHTML(item.name)}</strong>
                        <span>${escapeHTML(item.description || (item.captureOnly ? 'pcap device' : 'interface'))}</span>
                    </div>
                    <p>${previewAddresses(item)}</p>
                    ${renderInterfaceTags(item)}
                </button>
            `;
        }).join('');
    }

    return `
        <aside class="sidebar panel">
            <div class="brand-row">
                <div>
                    <span class="eyebrow">Local Network Settings</span>
                    <h1>Interfaces</h1>
                </div>
            </div>

            <div class="sidebar-controls">
                <label class="search-field">
                    <span class="eyebrow">Search</span>
                    <input id="interface-search" type="text" placeholder="Name, address, flag" autocomplete="off" />
                </label>
                <button class="ghost-button" type="button" id="refresh-interfaces">Refresh</button>
            </div>

            <div class="list-header">
                <span class="eyebrow">Detected</span>
                <strong>${items.length}</strong>
            </div>

            <div class="interface-list">
                ${listMarkup}
            </div>
        </aside>
    `;
}

function renderSelectedInterface(state, item) {
    if (!item) {
        return renderStateLayout('workspace', 'No interface selected', 'Adjust the search or refresh the interface inventory.');
    }

    return `
        <main class="workspace">
            ${state.snapshot?.captureWarning ? renderMessageBanner('pcap notice', state.snapshot.captureWarning) : ''}

            <header class="panel interface-header">
                <div>
                    <span class="eyebrow">Selected Interface</span>
                    <h2>${escapeHTML(item.name)}</h2>
                    ${item.description ? `<p>${escapeHTML(item.description)}</p>` : ''}
                </div>
                <div class="badge-row">
                    ${interfaceBadges(item)}
                </div>
            </header>

            <div class="content-grid">
                <div class="content-stack">
                    <section class="panel section-panel">
                        <div class="section-heading">
                            <div>
                                <span class="eyebrow">System Addresses</span>
                                <h3>Addresses from the OS</h3>
                            </div>
                        </div>
                        ${renderDataList(item.systemAddresses, 'No system-reported addresses were returned.')}
                    </section>

                    <section class="panel section-panel">
                        <div class="section-heading">
                            <div>
                                <span class="eyebrow">Capture Addresses</span>
                                <h3>Addresses from gopacket/pcap</h3>
                            </div>
                        </div>
                        ${renderDataList(item.captureAddresses, 'No pcap-reported addresses were returned.')}
                    </section>

                    <section class="panel section-panel">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">pcap Flags</span>
                                <h3>Capture visibility</h3>
                            </div>
                        </div>
                        ${renderFlagList(item.captureFlags, 'No pcap flags reported.')}
                    </section>
                </div>

                <aside class="detail-stack">
                    <section class="panel section-panel">
                        <div class="section-heading section-heading--tight">
                            <div>
                                <span class="eyebrow">Overview</span>
                                <h3>Basic facts</h3>
                            </div>
                        </div>
                        ${renderOverviewRows(item)}
                    </section>
                </aside>
            </div>
        </main>
    `;
}

export function renderLocalNetworkModule({items, selected, state}) {
    const detail = state.snapshot?.interfaces?.length
        ? `${state.snapshot.interfaces.length} interfaces available`
        : 'Inspect interfaces';
    const body = state.interfacesLoading
        ? renderStateLayout('workspace', 'Loading interfaces', 'Collecting interface data.')
        : state.interfaceError
            ? renderStateLayout('workspace', 'Unable to load interfaces', state.interfaceError, 'error')
            : renderSelectedInterface(state, selected);

    return `
        <div class="module-frame">
            ${renderModuleTopbar('Local Network Settings', detail)}
            <div class="app-shell">
                ${renderSidebar({items, selected, state})}
                ${body}
            </div>
        </div>
    `;
}
