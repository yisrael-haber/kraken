/* Kraken replacement for the CMake-generated ares_build.h. ares.h includes the
 * system headers these flags name, then uses the two types. */
#ifndef __CARES_BUILD_H
#define __CARES_BUILD_H

#ifdef _WIN32
#  define CARES_TYPEOF_ARES_SOCKLEN_T int
#  define CARES_TYPEOF_ARES_SSIZE_T   __int64
#  define CARES_HAVE_SYS_TYPES_H
#  define CARES_HAVE_WINSOCK2_H
#  define CARES_HAVE_WS2TCPIP_H
#  define CARES_HAVE_WINDOWS_H
#else
#  define CARES_TYPEOF_ARES_SOCKLEN_T socklen_t
#  define CARES_TYPEOF_ARES_SSIZE_T   ssize_t
#  define CARES_HAVE_SYS_TYPES_H
#  define CARES_HAVE_SYS_SOCKET_H
#  define CARES_HAVE_SYS_SELECT_H
#endif

#endif /* __CARES_BUILD_H */
