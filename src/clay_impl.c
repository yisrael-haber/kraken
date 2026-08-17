#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_glue.h"
#include "sokol_log.h"
#include <stdio.h>

#define CLAY_IMPLEMENTATION
#include "clay.h"

#include "util/sokol_gl.h"
#include "fontstash.h"
#include "util/sokol_fontstash.h"
#define SOKOL_CLAY_IMPL
#include "sokol_clay.h"

void kraken_log(const char *message) {
    fprintf(stdout, "kraken: %s\n", message);
    fflush(stdout);
}
