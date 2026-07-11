import {escapeHTML, pill, renderMessageBanner, renderModuleTopbar} from './common';

const ENCRYPTION_TYPES = [
    ['aes256-cts-hmac-sha1-96', 'AES256-SHA1'],
    ['aes128-cts-hmac-sha1-96', 'AES128-SHA1'],
    ['aes256-cts-hmac-sha384-192', 'AES256-SHA2'],
    ['aes128-cts-hmac-sha256-128', 'AES128-SHA2'],
    ['rc4-hmac', 'RC4-HMAC'],
    ['des3-cbc-sha1-kd', 'DES3-SHA1'],
];

export function renderOfflineModule({state}) {
    const form = state.keytabForm;
    const busy = state.creatingKeytab;
    const result = state.keytabResult;
    return `
        <div class="module-frame module-frame--single">
            ${renderModuleTopbar('Offline tools')}
            <main class="single-panel-layout single-panel-layout--wide">
                <section class="offline-tool">
                    <header class="section-heading"><h2>Keytab builder</h2></header>
                    <form id="create-keytab-form" class="keytab-form">
                        <div class="compact-form-grid compact-form-grid--two">
                            <label class="form-field"><span>Principal</span><input type="text" name="principal" value="${escapeHTML(form.principal)}" placeholder="HTTP/web.lab.local" autocomplete="off" spellcheck="false" data-keytab-field="principal" ${busy ? 'disabled' : ''} /></label>
                            <label class="form-field"><span>Realm</span><input type="text" name="realm" value="${escapeHTML(form.realm)}" placeholder="LAB.LOCAL" autocomplete="off" spellcheck="false" data-keytab-field="realm" ${busy ? 'disabled' : ''} /></label>
                            <label class="form-field"><span>Password</span><input type="password" name="password" value="${escapeHTML(form.password)}" autocomplete="new-password" data-keytab-field="password" ${busy ? 'disabled' : ''} /></label>
                            <label class="form-field"><span>KVNO</span><input type="number" name="kvno" value="${escapeHTML(form.kvno)}" min="0" max="255" step="1" inputmode="numeric" data-keytab-field="kvno" ${busy ? 'disabled' : ''} /></label>
                            <label class="form-field keytab-form__filename"><span>File name</span><input type="text" name="fileName" value="${escapeHTML(form.fileName)}" placeholder="HTTP_web.lab.local.keytab" autocomplete="off" spellcheck="false" data-keytab-field="fileName" ${busy ? 'disabled' : ''} /></label>
                        </div>
                        <fieldset class="keytab-enctypes" ${busy ? 'disabled' : ''}>
                            <legend>Encryption types</legend>
                            <div class="keytab-enctypes__items">
                                ${ENCRYPTION_TYPES.map(([value, label]) => `
                                    <label class="keytab-enctype ${value.startsWith('aes') ? '' : 'keytab-enctype--compat'}">
                                        <input type="checkbox" value="${value}" data-keytab-encryption-type="${value}" ${form.encryptionTypes.includes(value) ? 'checked' : ''} />
                                        <span>${label}</span>
                                    </label>
                                `).join('')}
                            </div>
                        </fieldset>
                        <div class="form-actions keytab-form__actions"><button class="command-button command-button--primary" type="submit" ${busy ? 'disabled' : ''}>${busy ? 'Creating...' : 'Create keytab'}</button></div>
                    </form>
                </section>
                ${state.keytabError ? renderMessageBanner('Keytab', state.keytabError) : ''}
                ${result ? `
                    <div class="keytab-success">${pill('Created', 'success')}<code>${escapeHTML(result.path)}</code></div>
                ` : ''}
            </main>
        </div>
    `;
}
