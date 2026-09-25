/* Kraken wolfSSL configuration: TLS 1.2 and 1.3, client and server, over
 * Kraken's I/O callbacks. Selected by -DWOLFSSL_USER_SETTINGS. */
#ifndef KRAKEN_WOLFSSL_USER_SETTINGS_H
#define KRAKEN_WOLFSSL_USER_SETTINGS_H

/* NO_FILESYSTEM drops wolfSSL's own <stdio.h> include, but its string helpers
 * still call vsnprintf. */
#include <stdio.h>
/* wolfSSH (built against this config) uses winsock SOCKET types on Windows even
 * with custom I/O; NO_SOCK stops wolfSSL from pulling winsock in, so do it here. */
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

/* Platform: no files and no OS sockets; all I/O goes through the callbacks set
 * with wolfSSL_SSLSetIORecv/Send. Linux seeds the RNG with getrandom(), since
 * NO_FILESYSTEM removes the /dev/urandom path; Windows uses its own API. */
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define NO_FILESYSTEM
#ifdef __linux__
#define WOLFSSL_GETRANDOM
#endif

/* TLS: versions 1.2 and 1.3 and the extensions scripts use or peers expect. */
#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define HAVE_ALPN
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_HKDF
/* Keeps the peer's certificate chain for session:info(). */
#define SESSION_CERTS
/* Each Kraken session has its own context and never resumes, so the global
 * resumption cache (about 630 KB of static memory with SESSION_CERTS) is unused. */
#define NO_SESSION_CACHE

/* Public keys: RSA (with PSS), ECC P-256/384/521, X25519, Ed25519, FFDHE. */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_4096
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC521
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define HAVE_CURVE25519
#define HAVE_ED25519
#define HAVE_FFDHE_2048

/* Ciphers and hashes: AES-GCM, ChaCha20-Poly1305, SHA-2. */
#define HAVE_AESGCM
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* Legacy algorithms and features TLS 1.2/1.3 do not need. */
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_DSA
#define NO_PSK
#define NO_PWDBASED

#endif
