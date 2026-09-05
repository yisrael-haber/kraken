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

void kraken_sokol_log(const char *tag, uint32_t log_level, uint32_t log_item, const char *message, uint32_t line_nr, const char *filename, void *user_data);
void kraken_on_hover(void *user_data);
uint8_t kraken_pointer_state(void);
float kraken_pointer_x(void);
float kraken_pointer_y(void);
