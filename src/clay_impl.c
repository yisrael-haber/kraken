#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_glue.h"
#include "sokol_log.h"
#include <stdint.h>

#define CLAY_IMPLEMENTATION
#include "clay.h"

#include "util/sokol_gl.h"
#include "fontstash.h"
#include "util/sokol_fontstash.h"
#define SOKOL_CLAY_IMPL
#include "sokol_clay.h"

extern void kraken_handle_hover(float pointer_x, float pointer_y, uint8_t pointer_state, void *user_data);

static void kraken_hover_bridge(Clay_ElementId element_id, Clay_PointerData pointer_data, void *user_data) {
    (void)element_id;
    kraken_handle_hover(pointer_data.position.x, pointer_data.position.y, (uint8_t)pointer_data.state, user_data);
}

void kraken_on_hover(void *user_data) {
    Clay_OnHover(kraken_hover_bridge, user_data);
}

uint8_t kraken_pointer_state(void) {
    return (uint8_t)Clay_GetPointerState().state;
}

float kraken_pointer_x(void) {
    return Clay_GetPointerState().position.x;
}

float kraken_pointer_y(void) {
    return Clay_GetPointerState().position.y;
}
