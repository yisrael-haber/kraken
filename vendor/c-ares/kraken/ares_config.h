/* Kraken replacement for the CMake-generated ares_config.h (Linux only; Windows
 * uses the upstream config-win32.h). Only the record codec is compiled, and it
 * needs only these: without them it fails to build or, for the two INET6
 * entries, redefines the system's AF_INET6 and PF_INET6. Everything else the
 * CMake header lists selects resolver code or a libc routine over c-ares' own. */
#define HAVE_STDINT_H 1
#define HAVE_ERRNO_H 1
#define HAVE_STRUCT_SOCKADDR_IN6 1
#define HAVE_STRUCT_TIMEVAL 1
#define HAVE_AF_INET6 1
#define HAVE_PF_INET6 1
