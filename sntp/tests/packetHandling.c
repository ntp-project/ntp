#include "config.h"
#include "ntp_debug.h"
#include "ntp_stdlib.h"
#include "ntp_types.h"

#include "sntptest.h"

#include "kod_management.h"
#include "main.h"
#include "networking.h"
#include "ntp.h"

#include "unity.h"

void setUp(void);
int LfpEquality(const l_fp expected, const l_fp actual);

void test_GenerateUnauthenticatedPacket(void);
void test_GenerateAuthenticatedPacket(void);
void test_OffsetCalculationPositiveOffset(void);
void test_OffsetCalculationNegativeOffset(void);
void test_HandleUnusableServer(void);
void test_HandleUnusablePacket(void);
void test_HandleServerAuthenticationFailure(void);
void test_HandleKodDemobilize(void);
void test_HandleKodRate(void);
void test_HandleCorrectPacket(void);

void dump_mac(const char *test_func, u_char *pmac, size_t octets);


void
setUp(void)
{ 
	init_lib(); 
}


int
LfpEquality(
	const l_fp	expected,
	const l_fp 	actual
	)
{
	return !!(L_ISEQU(&expected, &actual));
}


void
test_GenerateUnauthenticatedPacket(void)
{
	struct pkt	testpkt;
	struct timeval	xmt;
	l_fp		expected_xmt, actual_xmt;

	GETTIMEOFDAY(&xmt, NULL);
	xmt.tv_sec += JAN_1970;

	TEST_ASSERT_EQUAL(LEN_PKT_NOMAC,
			  generate_pkt(&testpkt, &xmt, 0, NULL));

	TEST_ASSERT_EQUAL(LEAP_NOTINSYNC, PKT_LEAP(testpkt.li_vn_mode));
	TEST_ASSERT_EQUAL(NTP_VERSION, PKT_VERSION(testpkt.li_vn_mode));
	TEST_ASSERT_EQUAL(MODE_CLIENT, PKT_MODE(testpkt.li_vn_mode));

	TEST_ASSERT_EQUAL(STRATUM_UNSPEC, PKT_TO_STRATUM(testpkt.stratum));
	TEST_ASSERT_EQUAL(8, testpkt.ppoll);

	TVTOTS(&xmt, &expected_xmt);
	NTOHL_FP(&testpkt.xmt, &actual_xmt);
	TEST_ASSERT_TRUE(LfpEquality(expected_xmt, actual_xmt));
}


void
test_GenerateAuthenticatedPacket(void)
{
#ifdef OPENSSL

	const int EXPECTED_PKTLEN = LEN_PKT_NOMAC + KEY_MAC_LEN + MAX_MDG_LEN;

	struct key	testkey;
	struct pkt	testpkt;
	struct timeval	xmt;
	l_fp		expected_xmt, actual_xmt;
	const char key[] = "123456789";
	size_t		mac_sz;
	const u_char	expected_mac[] = {
				0x74, 0x66, 0x61, 0x32,
				0xfa, 0x44, 0xd7, 0x22,
				0x97, 0x27, 0xca, 0xac,
				0x95, 0xd9, 0x13, 0xe2,
				0x5f, 0xc5, 0x7e, 0x1f
			};

	testkey.next = NULL;
	testkey.key_id = 30;
	strlcpy(testkey.key_seq, key, sizeof(testkey.key_seq));
	testkey.key_len = strlen(testkey.key_seq);
	strlcpy(testkey.typen, "SHA256", sizeof(testkey.typen));
	testkey.typei = keytype_from_text(testkey.typen, NULL);

	xmt.tv_sec = JAN_1970;
	xmt.tv_usec = 0;

	TEST_ASSERT_EQUAL(EXPECTED_PKTLEN,
			  generate_pkt(&testpkt, &xmt, testkey.key_id,
			  &testkey));

	TEST_ASSERT_EQUAL(LEAP_NOTINSYNC, PKT_LEAP(testpkt.li_vn_mode));
	TEST_ASSERT_EQUAL(NTP_VERSION, PKT_VERSION(testpkt.li_vn_mode));
	TEST_ASSERT_EQUAL(MODE_CLIENT, PKT_MODE(testpkt.li_vn_mode));

	TEST_ASSERT_EQUAL(STRATUM_UNSPEC, PKT_TO_STRATUM(testpkt.stratum));
	TEST_ASSERT_EQUAL(8, testpkt.ppoll);

	TVTOTS(&xmt, &expected_xmt);
	NTOHL_FP(&testpkt.xmt, &actual_xmt);
	TEST_ASSERT_TRUE(LfpEquality(expected_xmt, actual_xmt));

	TEST_ASSERT_EQUAL(testkey.key_id, ntohl(testpkt.exten[0]));

	TEST_ASSERT_EQUAL(sizeof(expected_mac), MAX_MDG_LEN);
 	mac_sz = make_mac(&testpkt, LEN_PKT_NOMAC, &testkey,
			  &testpkt.exten[1], MAX_MDG_LEN);
	TEST_ASSERT_EQUAL(mac_sz, MAX_MDG_LEN);
	dump_mac(__func__, (void *)&testpkt.exten[1], mac_sz);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_mac, (void *)&testpkt.exten[1],
				     mac_sz);

#else	/* !OPENSSL follows */

	TEST_IGNORE_MESSAGE("OpenSSL not found, skipping...");

#endif
}


void
test_OffsetCalculationPositiveOffset(void)
{
	struct pkt	rpkt;
	l_fp		reftime, tmp;
	struct timeval	dst;
	double		offset, precision, synch_distance;

	rpkt.precision = -16; /* 0,000015259 */
	rpkt.rootdelay = HTONS_FP(DTOUFP(0.125));
	rpkt.rootdisp = HTONS_FP(DTOUFP(0.25));

	/* Synch Distance: (0.125+0.25)/2.0 == 0.1875 */
	get_systime(&reftime);
	HTONL_FP(&reftime, &rpkt.reftime);

	/* T1 - Originate timestamp */
	tmp.l_ui = 1000000000UL;
	tmp.l_uf = 0UL;
	HTONL_FP(&tmp, &rpkt.org);

	/* T2 - Receive timestamp */
	tmp.l_ui = 1000000001UL;
	tmp.l_uf = 2147483648UL;
	HTONL_FP(&tmp, &rpkt.rec);

	/* T3 - Transmit timestamp */
	tmp.l_ui = 1000000002UL;
	tmp.l_uf = 0UL;
	HTONL_FP(&tmp, &rpkt.xmt);

	/* T4 - Destination timestamp as standard timeval */
	tmp.l_ui = 1000000001UL;
	tmp.l_uf = 0UL;
	TSTOTV(&tmp, &dst);
	dst.tv_sec -= JAN_1970;

	offset_calculation(&rpkt, LEN_PKT_NOMAC, &dst, &offset, &precision, &synch_distance);

	TEST_ASSERT_EQUAL_DOUBLE(1.25, offset);
	TEST_ASSERT_EQUAL_DOUBLE(1. / ULOGTOD(16), precision);
	/* 1.1250150000000001 ? */
	TEST_ASSERT_EQUAL_DOUBLE(1.125015, synch_distance);
}


void
test_OffsetCalculationNegativeOffset(void)
{
	struct pkt	rpkt;
	l_fp		reftime, tmp;
	struct timeval	dst;
	double		offset, precision, synch_distance;

	rpkt.precision = -1;
	rpkt.rootdelay = HTONS_FP(DTOUFP(0.5));
	rpkt.rootdisp = HTONS_FP(DTOUFP(0.5));

	/* Synch Distance is (0.5+0.5)/2.0, or 0.5 */
	get_systime(&reftime);
	HTONL_FP(&reftime, &rpkt.reftime);

	/* T1 - Originate timestamp */
	tmp.l_ui = 1000000001UL;
	tmp.l_uf = 0UL;
	HTONL_FP(&tmp, &rpkt.org);

	/* T2 - Receive timestamp */
	tmp.l_ui = 1000000000UL;
	tmp.l_uf = 2147483648UL;
	HTONL_FP(&tmp, &rpkt.rec);

	/*/ T3 - Transmit timestamp */
	tmp.l_ui = 1000000001UL;
	tmp.l_uf = 2147483648UL;
	HTONL_FP(&tmp, &rpkt.xmt);

	/* T4 - Destination timestamp as standard timeval */
	tmp.l_ui = 1000000003UL;
	tmp.l_uf = 0UL;

	TSTOTV(&tmp, &dst);
	dst.tv_sec -= JAN_1970;

	offset_calculation(&rpkt, LEN_PKT_NOMAC, &dst, &offset, &precision, &synch_distance);

	TEST_ASSERT_EQUAL_DOUBLE(-1, offset);
	TEST_ASSERT_EQUAL_DOUBLE(1. / ULOGTOD(1), precision);
	TEST_ASSERT_EQUAL_DOUBLE(1.3333483333333334, synch_distance);
}


void
test_HandleUnusableServer(void)
{
	struct pkt	rpkt;
	sockaddr_u	host;
	int		rpktl;

	ZERO(rpkt);
	ZERO(host);
	rpktl = SERVER_UNUSEABLE;
	TEST_ASSERT_EQUAL(-1, handle_pkt(rpktl, &rpkt, &host, ""));
}


void
test_HandleUnusablePacket(void)
{
	struct pkt	rpkt;
	sockaddr_u	host;
	int		rpktl;

	ZERO(rpkt);
	ZERO(host);
	rpktl = PACKET_UNUSEABLE;
	TEST_ASSERT_EQUAL(1, handle_pkt(rpktl, &rpkt, &host, ""));
}


void
test_HandleServerAuthenticationFailure(void)
{
	struct pkt	rpkt;
	sockaddr_u	host;
	int		rpktl;

	ZERO(rpkt);
	ZERO(host);
	rpktl = SERVER_AUTH_FAIL;
	TEST_ASSERT_EQUAL(1, handle_pkt(rpktl, &rpkt, &host, ""));
}


void
test_HandleKodDemobilize(void)
{
	static const char *	HOSTNAME = "192.0.2.1";
	static const char *	REASON = "DENY";
	struct pkt		rpkt;
	sockaddr_u		host;
	int			rpktl;
	struct kod_entry *	entry;

	rpktl = KOD_DEMOBILIZE;
	ZERO(rpkt);
	memcpy(&rpkt.refid, REASON, 4);
	ZERO(host);
	host.sa4.sin_family = AF_INET;
	host.sa4.sin_addr.s_addr = inet_addr(HOSTNAME);

	/* Test that the KOD-entry is added to the database. */
	kod_init_kod_db("/dev/null", TRUE);

	TEST_ASSERT_EQUAL(1, handle_pkt(rpktl, &rpkt, &host, HOSTNAME));

	TEST_ASSERT_EQUAL(1, search_entry(HOSTNAME, &entry));
	TEST_ASSERT_EQUAL_MEMORY(REASON, entry->type, 4);
}


void
test_HandleKodRate(void)
{
	struct 	pkt	rpkt;
	sockaddr_u	host;
	int		rpktl;

	ZERO(rpkt);
	ZERO(host);
	rpktl = KOD_RATE;
	TEST_ASSERT_EQUAL(1, handle_pkt(rpktl, &rpkt, &host, ""));
}


void
test_HandleCorrectPacket(void)
{
	struct pkt	rpkt;
	sockaddr_u	host;
	int		rpktl;
	l_fp		now;

	/* We don't want our testing code to actually change the system clock. */
	TEST_ASSERT_FALSE(ENABLED_OPT(STEP));
	TEST_ASSERT_FALSE(ENABLED_OPT(SLEW));

	get_systime(&now);
	HTONL_FP(&now, &rpkt.reftime);
	HTONL_FP(&now, &rpkt.org);
	HTONL_FP(&now, &rpkt.rec);
	HTONL_FP(&now, &rpkt.xmt);
	rpktl = LEN_PKT_NOMAC;
	ZERO(host);
	AF(&host) = AF_INET;

	TEST_ASSERT_EQUAL(0, handle_pkt(rpktl, &rpkt, &host, ""));
}


/*
 * Dump a MAC in a form easy to cut and paste into the expected declaration.
 * This is noisy in the test logs but they're generally examined only when
 * adding another digest algorithm to the unit tests, where they are very
 * helpful as the assertion failure messages do not provide the generated
 * MAC to put into the expected declaration.
 */
void dump_mac(
	const char *	test_func,
	u_char *	pmac,
	size_t		octets
)
{
	char	dump[2048];
	size_t	dc = 0;
	size_t	idx;

	dc += snprintf(dump + dc, sizeof(dump) - dc,
		"\n%s\n"
		"\tconst u_char\texpected_mac[] = {",
		test_func);

	for (idx = 0; idx < octets; idx++) {
		if (0 == idx % 4) {
			dc += snprintf(dump + dc, sizeof(dump) - dc, "\n\t\t\t\t");
		}
		if (dc < sizeof(dump)) {
			dc += snprintf(dump + dc, sizeof(dump) - dc,
				"0x%02x, ", pmac[idx]);
		}
	}

	/* wipe out final comma and space */
	if (dc > 2) {
		dc -= 2;
	}
	if (dc < sizeof(dump)) {
		dc += snprintf(dump + dc, sizeof(dump) - dc, "\n\t\t\t};");
	}

	msyslog(LOG_DEBUG, "%s", dump);
}

/* packetHandling.c */
