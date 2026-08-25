#include <config.h>

#include <ctype.h>
#include <string.h>
#include "ntp_assert.h"
#include "ntp_malloc.h"
#include "l_stdlib.h"

#ifndef HAVE_STRDUP
# undef STRDUP_EMPTY_UNIT
char *strdup(const char *s);
char *
strdup(
	const char *s
	)
{
	size_t	octets;
	char *	cp;

	REQUIRE(s);
	octets = strlen(s) + 1;
	if ((cp = malloc(octets)) == NULL)
		return NULL;
	memcpy(cp, s, octets);

	return cp;
}
#endif

#ifndef HAVE__STRUPR
char *
_strupr(char *s)
{
	char *pch;

	for (pch = s; '\0' != *pch; pch++) {
		*pch = toupper((u_char)*pch);
	}
	return s;
}
#endif

#ifndef HAVE_STRNLEN
# undef STRDUP_EMPTY_UNIT
size_t strnlen(const char *s, size_t n)
{
	const char *e = memchr(s, 0, n);
	return e ? (size_t)(e - s) : n;
}
#endif

NONEMPTY_TRANSLATION_UNIT
