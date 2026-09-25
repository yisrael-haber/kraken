/* Kraken: ares_is_onion_domain lives in the resolver's ares_getnameinfo.c,
 * which is not vendored. The record code references it from a resolver
 * helper Kraken never calls; this keeps unoptimized builds linking. */
#include "ares_private.h"
#include <string.h>

static ares_bool_t ends_with(const char *name, const char *suffix)
{
  size_t name_len   = strlen(name);
  size_t suffix_len = strlen(suffix);
  return name_len >= suffix_len &&
             ares_strcaseeq(name + name_len - suffix_len, suffix)
           ? ARES_TRUE
           : ARES_FALSE;
}

ares_bool_t ares_is_onion_domain(const char *name)
{
  return ends_with(name, ".onion") || ends_with(name, ".onion.") ? ARES_TRUE
                                                                  : ARES_FALSE;
}
