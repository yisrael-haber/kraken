import {escapeHTML, renderMessageBanner, renderModuleTopbar} from './common';

const ENCRYPTION_TYPES = [
    ['aes256-cts-hmac-sha1-96', 'AES256-SHA1'],
    ['aes128-cts-hmac-sha1-96', 'AES128-SHA1'],
    ['aes256-cts-hmac-sha384-192', 'AES256-SHA2'],
    ['aes128-cts-hmac-sha256-128', 'AES128-SHA2'],
    ['rc4-hmac', 'RC4-HMAC'],
    ['des3-cbc-sha1-kd', 'DES3-SHA1'],
];

export function renderKeytabModule({state}) {
    const form = state.keytabForm;
    const busy = state.creatingKeytab;
    const result = state.keytabResult;
    return `
        <div class="module-frame">
            ${renderModuleTopbar('Keytab builder')}
            <main class="single-panel-layout">
                <form id="create-keytab-form" class="keytab-form">
                    <div class="keytab-fields">
                        <wa-input label="Principal" type="text" name="principal" value="${escapeHTML(form.principal)}" placeholder="HTTP/web.lab.local" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-keytab-field="principal" ${busy ? 'disabled' : ''}></wa-input>
                        <wa-input label="Realm" type="text" name="realm" value="${escapeHTML(form.realm)}" placeholder="LAB.LOCAL" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-keytab-field="realm" ${busy ? 'disabled' : ''}></wa-input>
                        <wa-input label="Password" type="password" name="password" value="${escapeHTML(form.password)}" autocomplete="new-password" appearance="filled" size="xs" data-keytab-field="password" ${busy ? 'disabled' : ''}></wa-input>
                        <wa-number-input label="KVNO" name="kvno" value="${escapeHTML(form.kvno)}" min="0" max="255" step="1" appearance="filled" size="xs" data-keytab-field="kvno" ${busy ? 'disabled' : ''}></wa-number-input>
                        <wa-input class="keytab-form__filename" label="File name" type="text" name="fileName" value="${escapeHTML(form.fileName)}" placeholder="HTTP_web.lab.local.keytab" autocomplete="off" spellcheck="false" appearance="filled" size="xs" data-keytab-field="fileName" ${busy ? 'disabled' : ''}></wa-input>
                    </div>
                    <wa-checkbox-group label="Encryption types" hint="RC4-HMAC and DES3-SHA1 are provided for compatibility." orientation="horizontal" size="xs">
                        ${ENCRYPTION_TYPES.map(([value, label]) => `
                            <wa-checkbox name="encryptionTypes" value="${value}" data-keytab-encryption-type="${value}" ${form.encryptionTypes.includes(value) ? 'checked' : ''} ${busy ? 'disabled' : ''}>
                                ${label}
                            </wa-checkbox>
                        `).join('')}
                    </wa-checkbox-group>
                    <div class="form-actions">
                        <wa-button variant="brand" appearance="outlined" size="xs" type="submit" ${busy ? 'loading disabled' : ''}>Create keytab</wa-button>
                    </div>
                </form>
                ${state.keytabError ? renderMessageBanner('Keytab', state.keytabError) : ''}
                ${result ? `
                    <wa-callout class="message-banner" variant="success" appearance="outlined" size="s">
                        <strong>Keytab created</strong>
                        <p><code>${escapeHTML(result.path)}</code></p>
                    </wa-callout>
                ` : ''}
            </main>
        </div>
    `;
}
