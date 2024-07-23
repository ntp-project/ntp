/*
 * ntp_md5.h: deal with md5.h headers
 *
 * Use the system MD5 if available, otherwise use libisc's.
 * Yes, MD5 has been deprecated.  Nevertheless, ntpd IPv6 refid
 * calculation uses MD5 to derive a 32-bit refid from a 128-bit
 * IPv6 address.  This use is retained to avoid breaking loop
 * detection that would be triggered by such change, and because
 * we are not depending on cryptographic strength for such use.
 */
#ifndef NTP_MD5_H
#define NTP_MD5_H

/* Use the system MD5 or fall back on libisc's */
#if defined HAVE_MD5_H && defined HAVE_MD5INIT
# include <md5.h>
# define ntp_md5_init(c)		MD5Init(c)
# define ntp_md5_update(c, p, s)	MD5Update(c, (const void *)(p), s)
# define ntp_md5_final(d, c)		MD5Final(d, c)
#else
# include "isc/md5.h"
typedef isc_md5_t			MD5_CTX;
# define MD5_DIGEST_LENGTH		ISC_MD5_DIGESTLENGTH
# define ntp_md5_init(c)		isc_md5_init(c)
# define ntp_md5_update(c, p, s)	isc_md5_update(c, (const void *)(p), s)
# define ntp_md5_final(d, c)		isc_md5_final((c), (d))	/* swapped */
#endif

#ifdef OPENSSL
# include <openssl/evp.h>
# include "libssl_compat.h"
# ifdef HAVE_OPENSSL_CMAC_H
#  include <openssl/cmac.h>
#  define CMAC			"AES128CMAC"
#  define AES_128_KEY_SIZE	16
# endif
#else	/* !OPENSSL follows */
/*
 * Provide OpenSSL-alike MD5 API if we're not using OpenSSL.  Most of this
 * is used only by sntp when building it --without-crypto.
 */

typedef MD5_CTX				EVP_MD_CTX;

# define NID_md5			4	/* from openssl/objects.h */
# define EVP_MAX_MD_SIZE		MD5_DIGEST_LENGTH

/*
 * The following is used only by sntp configured --without-crypto as ntpd
 * now uses explicit MD5 functions for MD5 uses which remain even where MD5
 * is unavailable in OpenSSL, such as FIPS OpenSSL.  Note that FIPS may be
 * available in the build environment but not at runtime, as is the case
 * with packaged NTP binaries.
 * The remaining uses of MD5 are IPv6 refids and mode 6 nonces.  ntpd does
 * go through OpenSSL when using MD5 for symmetric authentication.
 */
# define EVP_MD_CTX_free(c)		free(c)
# define EVP_MD_CTX_new()		calloc(1, sizeof(MD5_CTX))
# define EVP_get_digestbynid(t)		NULL
# define EVP_md5()			NULL
# define EVP_MD_CTX_init(c)
# define EVP_MD_CTX_set_flags(c, f)
# define EVP_DigestInit(c, dt)		(ntp_md5_init(c), 1)
# define EVP_DigestUpdate(c, p, s)	ntp_md5_update(c, p, s)
# define EVP_DigestFinal(c, d, pdl)		\
	do {					\
		ntp_md5_final((d), (c));	\
		*(pdl) = MD5_LENGTH;		\
	} while (FALSE)

#endif	/* OPENSSL */

#endif	/* NTP_MD5_H */
