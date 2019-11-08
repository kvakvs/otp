#ifndef CRYPTO_OPENSSL_CONFIG_H
#define CRYPTO_OPENSSL_CONFIG_H

/* Helper macro to construct a OPENSSL_VERSION_NUMBER.
 * See openssl/opensslv.h
 */
#include <openssl/opensslv.h>


#define PACKED_OPENSSL_VERSION(MAJ, MIN, FIX, P)                               \
  ((((((((MAJ << 8) | MIN) << 8) | FIX) << 8) | (P - 'a' + 1)) << 4) | 0xf)

#define PACKED_OPENSSL_VERSION_PLAIN(MAJ, MIN, FIX)                            \
  PACKED_OPENSSL_VERSION(MAJ, MIN, FIX, ('a' - 1))

#if OPENSSL_VERSION_NUMBER >= PACKED_OPENSSL_VERSION(0, 9, 8, 'o') &&          \
    !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDH) &&                    \
    !defined(OPENSSL_NO_ECDSA)
#define HAVE_EC
#endif

// (test for >= 1.1.1pre8)
#if OPENSSL_VERSION_NUMBER >= (PACKED_OPENSSL_VERSION_PLAIN(1, 1, 1) - 7) &&   \
    !defined(HAS_LIBRESSL) && defined(HAVE_EC)
#define HAVE_ED_CURVE_DH
#if OPENSSL_VERSION_NUMBER >= (PACKED_OPENSSL_VERSION_PLAIN(1, 1, 1))
#define HAVE_EDDSA
#endif
#endif

#endif // CRYPTO_OPENSSL_CONFIG_H
