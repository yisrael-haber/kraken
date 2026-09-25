/* WS_UserAuthData contains a bitfield union that Zig's C translation renders as
 * opaque, so these accessors read and set its fields from C, where the real
 * layout is known. */
#ifndef KRAKEN_SSH_SHIM_H
#define KRAKEN_SSH_SHIM_H

#include <wolfssh/ssh.h>

const unsigned char* krakenSshAuthUser(WS_UserAuthData* d, word32* len);
const unsigned char* krakenSshAuthPassword(WS_UserAuthData* d, word32* len);
const unsigned char* krakenSshAuthPublicKey(WS_UserAuthData* d, word32* len);
void krakenSshSetAuthPassword(WS_UserAuthData* d, const unsigned char* p, word32 len);

#endif
