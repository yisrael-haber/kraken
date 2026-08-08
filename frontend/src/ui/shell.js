import {escapeHTML} from './common';
import {
    MODULE_GLOBAL_SCRIPTING,
    MODULE_IDENTITIES,
    MODULE_KEYTAB,
    MODULE_OPERATIONS,
    MODULE_SERVICES,
    MODULE_TRANSPORT_SCRIPTS,
    VIEW_ADOPTED_IP,
} from '../app/state';

const NAVIGATION_GROUPS = [
    {
        key: 'scripting',
        label: 'Scripting',
        icon: 'file-code',
        children: [
            ['Global scripting', MODULE_GLOBAL_SCRIPTING],
            ['Transport scripts', MODULE_TRANSPORT_SCRIPTS],
        ],
    },
    {
        key: 'networkActions',
        label: 'Network Actions',
        icon: 'diagram-project',
        children: [
            ['Operations', MODULE_OPERATIONS],
            ['Services', MODULE_SERVICES],
        ],
    },
    {
        key: 'offlineTools',
        label: 'Offline Tools',
        icon: 'screwdriver-wrench',
        children: [
            ['Keytab Generator', MODULE_KEYTAB],
        ],
    },
];

function selectedModule(view) {
    return view === VIEW_ADOPTED_IP ? MODULE_IDENTITIES : view;
}

function renderNavigationGroup(group, selected, expandedGroups) {
    const containsSelection = group.children.some(([, module]) => module === selected);
    const expanded = expandedGroups[group.key] || containsSelection;
    return `
        <wa-tree-item data-navigation-group="${group.key}" ${expanded ? 'expanded' : ''}>
            <wa-icon slot="prefix" library="kraken" name="${group.icon}"></wa-icon>
            ${group.label}
            ${group.children.map(([label, module]) => `
                <wa-tree-item data-open-module="${module}" ${selected === module ? 'selected' : ''}>
                    ${label}
                </wa-tree-item>
            `).join('')}
        </wa-tree-item>
    `;
}

function renderConfigurationDirectory(state) {
    if (state.configurationDirectoryError) {
        return `<span class="wa-caption-xs">${escapeHTML(state.configurationDirectoryError)}</span>`;
    }
    if (!state.configurationDirectory) {
        return '<span class="wa-caption-xs">Resolving path.</span>';
    }
    return `
        <code class="wa-caption-xs" title="${escapeHTML(state.configurationDirectory)}">${escapeHTML(state.configurationDirectory)}</code>
        <wa-copy-button
            value="${escapeHTML(state.configurationDirectory)}"
            copy-label="Copy config path"
            tooltip="copy"
        ></wa-copy-button>
    `;
}

export function renderAppShell({content, logo, state}) {
    const selected = selectedModule(state.view);
    const collapsed = state.navigationCollapsed;
    return `
        <wa-page class="app-shell ${collapsed ? 'app-shell--collapsed' : ''}">
            <header slot="header" class="wa-cluster wa-gap-xs">
                <wa-button appearance="plain" size="s" type="button" data-toggle-nav aria-label="Open navigation">
                    <wa-icon library="kraken" name="bars"></wa-icon>
                </wa-button>
                <strong>Kraken</strong>
            </header>

            <div slot="navigation-header" class="${collapsed ? 'wa-stack wa-gap-xs wa-align-items-center' : 'wa-split wa-gap-xs'}">
                <div class="sidebar-brand wa-cluster wa-gap-s">
                    <wa-avatar image="${logo}" label="Kraken logo" shape="rounded"></wa-avatar>
                    <strong class="sidebar-label wa-heading-l">Kraken</strong>
                </div>
                <wa-button class="sidebar-toggle" appearance="plain" size="xs" type="button" data-toggle-sidebar>
                    <wa-icon
                        library="system"
                        name="${collapsed ? 'angles-right' : 'angles-left'}"
                        label="${collapsed ? 'Expand sidebar' : 'Collapse sidebar'}"
                    ></wa-icon>
                </wa-button>
            </div>

            <nav slot="navigation" aria-label="Kraken workspace">
                <wa-tree selection="leaf" style="--indent-size: var(--wa-space-2xs)">
                    <wa-tree-item data-open-module="${MODULE_IDENTITIES}" ${selected === MODULE_IDENTITIES ? 'selected' : ''}>
                        <wa-icon slot="prefix" library="kraken" name="fingerprint"></wa-icon>
                        Identities
                    </wa-tree-item>
                    ${NAVIGATION_GROUPS.map((group) => renderNavigationGroup(
                        group,
                        selected,
                        state.navigationGroupsExpanded,
                    )).join('')}
                </wa-tree>
            </nav>

            <footer slot="navigation-footer" class="wa-stack wa-gap-2xs">
                <span class="wa-caption-2xs wa-text-uppercase">Config</span>
                <div class="wa-cluster wa-gap-2xs">
                    ${renderConfigurationDirectory(state)}
                </div>
            </footer>

            <main class="${state.view === MODULE_GLOBAL_SCRIPTING || state.view === MODULE_TRANSPORT_SCRIPTS ? 'app-main--script' : ''}">
                ${content}
            </main>
        </wa-page>
    `;
}
