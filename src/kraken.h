#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_glue.h"
#include "sokol_log.h"
#include "util/sokol_gl.h"
#include "fontstash.h"
#include "util/sokol_fontstash.h"
#include "clay.h"
#include "sokol_clay.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "wolfip.h"
#include <stdint.h>

void kraken_log(const char *message);
uint64_t kraken_now_us(void);
