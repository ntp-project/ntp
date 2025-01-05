/*
 *	digest support for NTP, MD5 and with OpenSSL more
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ntp_fp.h"
#include "ntp_string.h"
#include "ntp_stdlib.h"
#include "ntp.h"
#include "isc/string.h"

typedef struct {
	const void *	buf;
	size_t		len;
} robuffT;

typedef struct {
	void *		buf;
	size_t		len;
} rwbuffT;

bool	suppress_digest_errors;		/* for ntpq digest_alg_works() */


static inline void	digst_msyslog(int level, const char* fmt, ...) NTP_PRINTF(2, 3);

static inline void
digst_msyslog(
	int		level,
	const char *	fmt, 
	...
	)
{
	va_list	ap;

	if (!suppress_digest_errors) {
		va_start(ap, fmt);
		mvsyslog(level, fmt, ap);
		va_end(ap);
	}
}


#if defined(OPENSSL) && defined(ENABLE_CMAC)
static size_t
cmac_ctx_size(
	CMAC_CTX *	ctx
	)
{
	size_t mlen = 0;

	if (ctx) {
		EVP_CIPHER_CTX * 	cctx;
		if (NULL != (cctx = CMAC_CTX_get0_cipher_ctx (ctx)))
			mlen = EVP_CIPHER_CTX_block_size(cctx);
	}
	return mlen;
}
#endif	/* OPENSSL && ENABLE_CMAC */


/*
 * Allocate and initialize a digest context.  As a speed optimization,
 * take an idea from ntpsec and cache the context to avoid malloc/free
 * overhead in time-critical paths.  ntpsec also caches the algorithms
 * with each key.
 * This is not thread-safe, but that is not a problem at present.
 */
static EVP_MD_CTX *
get_md_ctx(
	int		nid
	)
{
#ifndef OPENSSL
	static MD5_CTX	md5_ctx;

	DEBUG_INSIST(NID_md5 == nid);
	ntp_md5_init(&md5_ctx);

	return &md5_ctx;
#else
	if (!EVP_DigestInit(digest_ctx, EVP_get_digestbynid(nid))) {
		digst_msyslog(LOG_ERR, "%s init failed", OBJ_nid2sn(nid));
		return NULL;
	}

	return digest_ctx;
#endif	/* OPENSSL */
}


static size_t
make_mac(
	const rwbuffT *	digest,
	int		ktype,
	const robuffT *	key,
	const robuffT *	msg
	)
{
	/*
	 * Compute digest of key concatenated with packet. Note: the
	 * key type and digest type have been verified when the key
	 * was created.
	 */
	size_t	retlen = 0;

#ifdef OPENSSL

	INIT_SSL();

	/* Check if CMAC key type specific code required */
#   ifdef ENABLE_CMAC
	if (ktype == NID_cmac) {
		CMAC_CTX *	ctx    = NULL;
		void const *	keyptr = key->buf;
		u_char		keybuf[AES_128_KEY_SIZE];

		/* adjust key size (zero padded buffer) if necessary */
		if (AES_128_KEY_SIZE > key->len) {
			memcpy(keybuf, keyptr, key->len);
			zero_mem((keybuf + key->len),
				 (AES_128_KEY_SIZE - key->len));
			keyptr = keybuf;
		}

		if (NULL == (ctx = CMAC_CTX_new())) {
			digst_msyslog(LOG_ERR, "MAC encrypt: CMAC %s CTX new failed.", CMAC);
			goto cmac_fail;
		}
		if (!CMAC_Init(ctx, keyptr, AES_128_KEY_SIZE, EVP_aes_128_cbc(), NULL)) {
			digst_msyslog(LOG_ERR, "MAC encrypt: CMAC %s Init failed.",    CMAC);
			goto cmac_fail;
		}
		if (cmac_ctx_size(ctx) > digest->len) {
			digst_msyslog(LOG_ERR, "MAC encrypt: CMAC %s buf too small.",  CMAC);
			goto cmac_fail;
		}
		if (!CMAC_Update(ctx, msg->buf, msg->len)) {
			digst_msyslog(LOG_ERR, "MAC encrypt: CMAC %s Update failed.",  CMAC);
			goto cmac_fail;
		}
		if (!CMAC_Final(ctx, digest->buf, &retlen)) {
			digst_msyslog(LOG_ERR, "MAC encrypt: CMAC %s Final failed.",   CMAC);
			retlen = 0;
		}
	  cmac_fail:
		if (ctx)
			CMAC_CTX_free(ctx);
	}
	else
#   endif /* ENABLE_CMAC */
	{	/* generic MAC handling */
		EVP_MD_CTX *	ctx;
		u_int		uilen = 0;

		ctx = get_md_ctx(ktype);
		if (NULL == ctx) {
			goto mac_fail;
		}
		if ((size_t)EVP_MD_CTX_size(ctx) > digest->len) {
			digst_msyslog(LOG_ERR, "MAC encrypt: MAC %s buf too small.",
				OBJ_nid2sn(ktype));
			goto mac_fail;
		}
		if (!EVP_DigestUpdate(ctx, key->buf, (u_int)key->len)) {
			digst_msyslog(LOG_ERR, "MAC encrypt: MAC %s Digest Update key failed.",
				OBJ_nid2sn(ktype));
			goto mac_fail;
		}
		if (!EVP_DigestUpdate(ctx, msg->buf, (u_int)msg->len)) {
			digst_msyslog(LOG_ERR, "MAC encrypt: MAC %s Digest Update data failed.",
				OBJ_nid2sn(ktype));
			goto mac_fail;
		}
		if (!EVP_DigestFinal(ctx, digest->buf, &uilen)) {
			digst_msyslog(LOG_ERR, "MAC encrypt: MAC %s Digest Final failed.",
				OBJ_nid2sn(ktype));
			uilen = 0;
		}
	  mac_fail:
		retlen = (size_t)uilen;
	}

#else /* !OPENSSL follows */

	if (NID_md5 == ktype) {
		EVP_MD_CTX *	ctx;

		ctx = get_md_ctx(ktype);
		if (digest->len < MD5_LENGTH) {
			msyslog(LOG_ERR, "%s", "MAC encrypt: MAC md5 buf too small.");
		} else {
			ntp_md5_init(ctx);
			ntp_md5_update(ctx, key->buf, key->len);
			ntp_md5_update(ctx, msg->buf, msg->len);
			ntp_md5_final(digest->buf, ctx);
			retlen = MD5_LENGTH;
		}
	} else {
		msyslog(LOG_ERR, "MAC encrypt: invalid key type %d", ktype);
	}

#endif /* !OPENSSL */

	return retlen;
}


/*
 * MD5authencrypt - add message digest to provided packet buffer.
 * Provided buffer must have room for 24 bytes of key ID and MAC.
 * Returns 0 on failure or length of added MAC including key ID.
 */
size_t
MD5authencrypt(
	int		type,		/* hash algorithm */
	const u_char *	key,		/* key pointer */
	size_t		klen,		/* key length */
	u_int32 *	pkt,		/* packet pointer */
	size_t		input_size	/* without MAC */
	)
{
	u_char	digest[EVP_MAX_MD_SIZE];
	rwbuffT digb = { digest, sizeof(digest) };
	robuffT keyb = { key, klen };
	robuffT msgb = { pkt, input_size };
	size_t	dlen;

	dlen = make_mac(&digb, type, &keyb, &msgb);
	if (0 == dlen) {
		return 0;
	}
	/*
	 * If the digest is longer than the 20 octets truncate it.  NTPv4
	 * MACs consist of a 4-octet key ID and a digest, total up to 24
	 * octets.  See RFC 7822 7.5.1.3 and 7.5.1.4.
	 * Use of a digest algorithm which produces more than 20 octets
	 * provides increased difficulty to forge even when truncated.
	 * The fleeting lifetime of an individual packet's MAC makes offline
	 * attack difficult.  The basic NTP packet is 48 octets, so it is
	 * not obvious that a digest of more than 20 octets is warranted.
	 */
	if (dlen > MAX_MDG_LEN) {
		dlen = MAX_MDG_LEN;
	}
	memcpy((u_char *)pkt + input_size + KEY_MAC_LEN, digest, dlen);
	return (dlen + KEY_MAC_LEN);
}


/*
 * MD5authdecrypt - verify MD5 message authenticator
 *
 * Returns TRUE if digest valid.
 */
bool
MD5authdecrypt(
	int		type,	/* hash algorithm */
	const u_char *	key,	/* key pointer */
	size_t		klen,	/* key length */
	u_int32	*	pkt,	/* packet pointer */
	size_t		length,	/* packet length */
	size_t		mac_size, /* including key id */
	keyid_t		keyno   /* key id (for err log) */
	)
{
	u_char	digest[EVP_MAX_MD_SIZE];
	rwbuffT digb = { digest, sizeof(digest) };
	robuffT keyb = { key, klen };
	robuffT msgb = { pkt, length };
	size_t	dlen;

	dlen = make_mac(&digb, type, &keyb, &msgb);

	/* If the digest is longer than 20 octets truncate. */
	if (dlen > MAX_MDG_LEN) {
		dlen = MAX_MDG_LEN;
	}
	if (mac_size != dlen + KEY_MAC_LEN) {
		digst_msyslog(LOG_ERR,
			"MAC decrypt: MAC length error: %u not %u for key %u",
			(u_int)mac_size, (u_int)(dlen + KEY_MAC_LEN), keyno);
		return FALSE;
	}
	return !isc_tsmemcmp(digest,
		 (u_char *)pkt + length + KEY_MAC_LEN, dlen);
}

/*
 * Calculate the reference id from the address. If it is an IPv4
 * address, use it as is. If it is an IPv6 address, do a md5 on
 * it and use the bottom 4 bytes.
 * The result is in network byte order for IPv4 addreseses.  For
 * IPv6, ntpd long differed in the hash calculated on big-endian
 * vs. little-endian because the first four bytes of the MD5 hash
 * were used as a u_int32 without any byte swapping.  This broke
 * the refid-based loop detection between mixed-endian systems.
 * In order to preserve behavior on the more-common little-endian
 * systems, the hash is now byte-swapped on big-endian systems to
 * match the little-endian hash.  This is ugly but it seems better
 * than changing the IPv6 refid calculation on the more-common
 * systems.
 * This is not thread safe, not a problem so far.
 */
u_int32
addr2refid(sockaddr_u *addr)
{
	static MD5_CTX	md5_ctx;
	union u_tag {
		u_char		digest[MD5_DIGEST_LENGTH];
		u_int32		addr_refid;
	} u;

	if (IS_IPV4(addr)) {
		return (NSRCADR(addr));
	}
	/* MD5 is not used for authentication here. */
	ntp_md5_init(&md5_ctx);
	ntp_md5_update(&md5_ctx, &SOCK_ADDR6(addr), sizeof(SOCK_ADDR6(addr)));
	ntp_md5_final(u.digest, &md5_ctx);
#ifdef WORDS_BIGENDIAN
	u.addr_refid = BYTESWAP32(u.addr_refid);
#endif
	return u.addr_refid;
}
