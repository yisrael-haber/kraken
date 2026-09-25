#include "ssh_shim.h"

const unsigned char* krakenSshAuthUser(WS_UserAuthData* d, word32* len) {
    *len = d->usernameSz;
    return d->username;
}
const unsigned char* krakenSshAuthPassword(WS_UserAuthData* d, word32* len) {
    *len = d->sf.password.passwordSz;
    return d->sf.password.password;
}
const unsigned char* krakenSshAuthPublicKey(WS_UserAuthData* d, word32* len) {
    *len = d->sf.publicKey.publicKeySz;
    return d->sf.publicKey.publicKey;
}
void krakenSshSetAuthPassword(WS_UserAuthData* d, const unsigned char* p, word32 len) {
    d->sf.password.password = p;
    d->sf.password.passwordSz = len;
}
