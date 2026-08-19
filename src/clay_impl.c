#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_glue.h"
#include "sokol_log.h"
#include <stdio.h>
#include <stdint.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

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

uint64_t kraken_now_us(void) {
#if defined(_WIN32)
    static LARGE_INTEGER frequency;
    if (frequency.QuadPart == 0) QueryPerformanceFrequency(&frequency);
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000) / frequency.QuadPart);
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000 + (uint64_t)now.tv_nsec / 1000;
#endif
}
