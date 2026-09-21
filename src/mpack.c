#include "mpack_config.h"
#include "../vendor/mpack/mpack.c"

void mpack_assert_fail(const char *message) {
    (void)message;
    __builtin_trap();
}
