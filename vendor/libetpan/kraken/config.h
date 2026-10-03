/* What libetpan's configure would generate for the SMTP, POP3 and IMAP clients over a
   caller-supplied stream: no sockets, TLS, SASL, iconv or database support. */
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDIO_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_FCNTL_H 1
#define HAVE_ERRNO_H 1
#define HAVE_TIME_H 1
#define LIBETPAN_REENTRANT 1
#ifdef _WIN32
#define HAVE_MINGW32_SYSTEM 1
#include <win_etpan.h>
#else
#define HAVE_UNISTD_H 1
#define HAVE_STRINGS_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_PTHREAD_H 1
#define HAVE_SYS_MMAN_H 1
#define HAVE_MMAP 1
#endif
