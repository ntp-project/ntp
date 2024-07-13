/*
 * sau_from_string
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "ntp_assert.h"
#include "ntp_stdlib.h"

/* Don't include ISC's version of IPv6 variables and structures */
#define ISC_IPV6_H 1
#include <isc/netaddr.h>
#include <isc/sockaddr.h>


/*
 * sau_from_string() - sockaddr_u from IP address string
 * Formerly named is_ip_address()
 */
int
sau_from_string(
	const char *	host,
	u_short		af,
	sockaddr_u *	addr
	)
{
	struct in_addr in4;
	struct addrinfo hints;
	struct addrinfo *result;
	struct sockaddr_in6 *resaddr6;
	char tmpbuf[128];
	char *pch;

	DEBUG_REQUIRE(host != NULL);
	DEBUG_REQUIRE(addr != NULL);

	ZERO_SOCK(addr);

	/*
	 * Try IPv4, then IPv6.  In order to handle the extended format
	 * for IPv6 scoped addresses (address%scope_ID), we'll use a local
	 * working buffer of 128 bytes.  The length is an ad-hoc value, but
	 * should be enough for this purpose; the buffer can contain a string
	 * of at least 80 bytes for scope_ID in addition to any IPv6 numeric
	 * addresses (up to 46 bytes), the delimiter character and the
	 * terminating NULL character.
	 */
	if (AF_UNSPEC == af || AF_INET == af)
		if (inet_pton(AF_INET, host, &in4) == 1) {
			AF(addr) = AF_INET;
			SET_ADDR4N(addr, in4.s_addr);

			return TRUE;
		}

	if (AF_UNSPEC == af || AF_INET6 == af)
		if (sizeof(tmpbuf) > strlen(host)) {
			if ('[' == host[0]) {
				strlcpy(tmpbuf, &host[1], sizeof(tmpbuf));
				pch = strchr(tmpbuf, ']');
				if (pch != NULL)
					*pch = '\0';
			} else {
				strlcpy(tmpbuf, host, sizeof(tmpbuf));
			}
			ZERO(hints);
			hints.ai_family = AF_INET6;
			hints.ai_flags |= AI_NUMERICHOST;
			if (getaddrinfo(tmpbuf, NULL, &hints, &result) == 0) {
				AF(addr) = AF_INET6;
				resaddr6 = QUIET_ALIGN_WARN(result->ai_addr);
				SET_ADDR6N(addr, resaddr6->sin6_addr);
				SET_SCOPE(addr, resaddr6->sin6_scope_id);

				freeaddrinfo(result);
				return TRUE;
			}
		}
	/*
	 * If we got here it was not an IP address
	 */
	return FALSE;
}
