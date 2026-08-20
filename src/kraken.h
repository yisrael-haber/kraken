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
void kraken_on_hover(void *user_data);
uint8_t kraken_pointer_state(void);
float kraken_pointer_x(void);
float kraken_pointer_y(void);
