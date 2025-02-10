#include "config.h"
#include "unity.h"
#include "ntp_types.h"

#include "sntptest.h"
#include "crypto.h"

#define CMAC "AES128CMAC"
#define CMAC_LENGTH 16


void test_MakeSHA256Mac(void);
void test_MakeSHA1Mac(void);
void test_MakeCMac(void);
void test_VerifySHA1(void);
void test_VerifySHA256(void);
void test_VerifyFailure(void);
void test_VerifyCMAC(void);
void test_PacketSizeNotMultipleOfFourBytes(void);

/* helper routines */
void Possibly_Corrupt_VerifySHA256(bool ForceFailure, const char *test_func);
void VerifyLocalCMAC(struct key *cmac);
void VerifyOpenSSLCMAC(struct key *cmac);
void dump_mac(const char *test_func, u_char *pmac, size_t octets);


void
test_MakeSHA1Mac(void)
{
#ifdef OPENSSL

	const char* PKT_DATA = "abcdefgh0123";
	const int PKT_LEN = strlen(PKT_DATA);
	const char* EXPECTED_DIGEST =
		"\x17\xaa\x82\x97\xc7\x17\x13\x6a\x9b\xa9"
		"\x63\x85\xb4\xce\xbe\x94\xa0\x97\x16\x1d";
	u_char actual[sizeof(EXPECTED_DIGEST) - 1];

	struct key sha1;
	sha1.next = NULL;
	sha1.key_id = 20;
	sha1.key_len = 7;
	memcpy(&sha1.key_seq, "sha1seq", sha1.key_len);
	strlcpy(sha1.typen, "SHA1", sizeof(sha1.typen));
	sha1.typei = keytype_from_text(sha1.typen, NULL);

	TEST_ASSERT(0 != sha1.typei);

	TEST_ASSERT_EQUAL(SHA1_LENGTH,
			  make_mac(PKT_DATA, PKT_LEN, &sha1, actual,
				   SHA1_LENGTH));

	TEST_ASSERT_EQUAL_MEMORY(EXPECTED_DIGEST, actual, sizeof(actual));

#else

	TEST_IGNORE_MESSAGE("OpenSSL not found, skipping...");

#endif	/* OPENSSL */
}


void
test_MakeSHA256Mac(void)
{
#ifdef OPENSSL

	const char	KEY[] = "SHA256 unit test key";
	const u_char	PAYLOAD[] = "packettestdata16";
	const size_t	PAYLOAD_LEN = sizeof(PAYLOAD) - 1;
	struct key	sk;
	const u_char	EXPECTED_DIGEST[] = {
				0x7c, 0xae, 0x05, 0xbe,
				0xaf, 0xe2, 0x02, 0xe9,
				0x64, 0x3c, 0xa9, 0x80,
				0xce, 0x55, 0x18, 0xb4,
				0xf9, 0xec, 0xc6, 0x57
			};
	u_char		actual[sizeof(EXPECTED_DIGEST)];

	sk.next = NULL;
	sk.key_id = 10;
	sk.key_len = sizeof(KEY) - 1;
	memcpy(&sk.key_seq, KEY, min(sizeof(sk.key_seq), sk.key_len));
	strlcpy(sk.typen, "SHA256", sizeof(sk.typen));
	sk.typei = keytype_from_text(sk.typen, NULL);

	TEST_ASSERT(0 != sk.typei);

	TEST_ASSERT_EQUAL(sizeof(actual),
		make_mac(PAYLOAD, PAYLOAD_LEN, &sk, actual,
			sizeof(actual)));
	dump_mac(__func__, actual, sizeof(actual));
	TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_DIGEST, actual, sizeof(actual));
#else

	TEST_IGNORE_MESSAGE("OpenSSL not found, skipping...");

#endif	/* OPENSSL */
}


void
test_MakeCMac(void)
{
#if defined(OPENSSL) && defined(ENABLE_CMAC)

	const char* PKT_DATA = "abcdefgh0123";
	const int PKT_LEN = strlen(PKT_DATA);
	const char* EXPECTED_DIGEST =
		"\xdd\x35\xd5\xf5\x14\x23\xd9\xd6"
		"\x38\x5d\x29\x80\xfe\x51\xb9\x6b";
	char actual[CMAC_LENGTH];
	struct key cmac;

	cmac.next = NULL;
	cmac.key_id = 30;
	cmac.key_len = CMAC_LENGTH;
	memcpy(&cmac.key_seq, "aes-128-cmac-seq", cmac.key_len);
	memcpy(&cmac.typen, CMAC, strlen(CMAC) + 1);

	TEST_ASSERT_EQUAL(CMAC_LENGTH,
		    make_mac(PKT_DATA, PKT_LEN, &cmac, actual, CMAC_LENGTH));

	TEST_ASSERT_EQUAL_MEMORY(EXPECTED_DIGEST, actual, CMAC_LENGTH);

#else

	TEST_IGNORE_MESSAGE("CMAC not enabled, skipping...");

#endif	/* OPENSSL */
}


void
test_VerifySHA1(void)
{
#ifdef OPENSSL

	const char* PKT_DATA =
	    "sometestdata"				/* Data */
	    "\0\0\0\0"					/* Key-ID (unused) */
	    "\xad\x07\xde\x36\x39\xa6\x77\xfa\x5b\xce"	/* MAC */
	    "\x2d\x8a\x7d\x06\x96\xe6\x0c\xbc\xed\xe1";
	const int PKT_LEN = 12;
	struct key sha1;

	sha1.next = NULL;
	sha1.key_id = 0;
	sha1.key_len = 7;
	memcpy(&sha1.key_seq, "sha1key", sha1.key_len);
	strlcpy(sha1.typen, "SHA1", sizeof(sha1.typen));
	sha1.typei = keytype_from_text(sha1.typen, NULL);

	TEST_ASSERT(0 != sha1.typei);

	TEST_ASSERT_TRUE(auth_md5(PKT_DATA, PKT_LEN, SHA1_LENGTH, &sha1));

#else

	TEST_IGNORE_MESSAGE("OpenSSL not found, skipping...");

#endif	/* OPENSSL */
}


void
Possibly_Corrupt_VerifySHA256(
	bool		ForceFailure,
	const char *	test_func
	)
{
#ifdef OPENSSL
	const char	KEY[] = "SHA256 unit test key";
	const u_char	PAYLOAD[] = "packettestdata16";
	const size_t	PAYLOAD_LEN = sizeof(PAYLOAD) - 1;
	const u_char	EXPECTED_DIGEST[] = {	/* from test_MakeSHA256Mac */
				0x7c, 0xae, 0x05, 0xbe,
				0xaf, 0xe2, 0x02, 0xe9,
				0x64, 0x3c, 0xa9, 0x80,
				0xce, 0x55, 0x18, 0xb4,
				0xf9, 0xec, 0xc6, 0x57
			};
	const size_t	DIGEST_LEN = sizeof(EXPECTED_DIGEST);
	struct key	sk;
	u_char		PKT_DATA[PAYLOAD_LEN + sizeof(sk.key_id)
			 + DIGEST_LEN];
	u_char *	p;

	sk.next = NULL;
	sk.key_id = 0;
	sk.key_len = sizeof(KEY) - 1;
	memcpy(&sk.key_seq, KEY, min(sizeof(sk.key_seq), sk.key_len));
	strlcpy(sk.typen, "SHA256", sizeof(sk.typen));
	sk.typei = keytype_from_text(sk.typen, NULL);

	TEST_ASSERT(0 != sk.typei);

	p = PKT_DATA;
	memcpy(p, PAYLOAD, PAYLOAD_LEN);	  p += PAYLOAD_LEN;
	memcpy(p, &sk.key_id, sizeof(sk.key_id)); p += sizeof(sk.key_id);
	memcpy(p, EXPECTED_DIGEST, DIGEST_LEN);
	if (ForceFailure) {
		(*p)++;
	}
	p += DIGEST_LEN;
	TEST_ASSERT_TRUE(sizeof(PKT_DATA) == p - PKT_DATA);

	if (!ForceFailure) {
		TEST_ASSERT_TRUE(auth_md5(PKT_DATA, PAYLOAD_LEN, DIGEST_LEN, &sk));
	} else {
		TEST_ASSERT_FALSE(auth_md5(PKT_DATA, PAYLOAD_LEN, DIGEST_LEN, &sk));
	}
#else

	TEST_IGNORE_MESSAGE("OpenSSL not found, skipping...");

#endif	/* OPENSSL */
}


void
test_VerifySHA256(void)
{
	Possibly_Corrupt_VerifySHA256(false, __func__);
}


void
test_VerifyFailure(void)
{
	Possibly_Corrupt_VerifySHA256(true, __func__);
}


void
test_VerifyCMAC(void)
{
	struct key cmac;

	cmac.next = NULL;
	cmac.key_id = 0;
	cmac.key_len = CMAC_LENGTH;
	memcpy(&cmac.key_seq, "aes-128-cmac-key", cmac.key_len);
	memcpy(&cmac.typen, CMAC, strlen(CMAC) + 1);

	VerifyOpenSSLCMAC(&cmac);
	VerifyLocalCMAC(&cmac);
}


void
VerifyOpenSSLCMAC(struct key *cmac)
{
#if defined(OPENSSL) && defined(ENABLE_CMAC)

	/* XXX: HMS: auth_md5 must be renamed/incorrect. */
	// TEST_ASSERT_TRUE(auth_md5(PKT_DATA, PKT_LEN, CMAC_LENGTH, cmac));
	TEST_IGNORE_MESSAGE("VerifyOpenSSLCMAC needs to be implemented, skipping...");

#else

	TEST_IGNORE_MESSAGE("CMAC not enabled, skipping...");

#endif	/* OPENSSL */
	return;
}


void
VerifyLocalCMAC(struct key *cmac)
{

	/* XXX: HMS: auth_md5 must be renamed/incorrect. */
	// TEST_ASSERT_TRUE(auth_md5(PKT_DATA, PKT_LEN, CMAC_LENGTH, cmac));

	TEST_IGNORE_MESSAGE("Hook in the local AES-128-CMAC check!");

	return;
}


void
test_PacketSizeNotMultipleOfFourBytes(void)
{
	/*
	 * We use a copy of test_MakeSHAKE128Mac(), but modify
	 * the packet length to 17.
	 */
#ifdef OPENSSL

	const char KEY[] = "SHAKE128 unit test key";
	const u_char PAYLOAD[] = "packettestdata_17";
	const size_t PAYLOAD_LEN = sizeof(PAYLOAD) - 1;
	const u_char EXPECTED_DIGEST[] =
		"\x62\x5A\x8F\xE4\x66\xCB\xF3\xA6"
		"\x73\x62\x68\x8D\x11\xB8\x42\xBB";
	u_char actual[sizeof(EXPECTED_DIGEST) - 1];
	struct key sk;

	sk.next = NULL;
	sk.key_id = 10;
	sk.key_len = sizeof(KEY) - 1;
	memcpy(&sk.key_seq, KEY, min(sizeof(sk.key_seq), sk.key_len));
	strlcpy(sk.typen, "SHAKE128", sizeof(sk.typen));
	sk.typei = keytype_from_text(sk.typen, NULL);

	TEST_ASSERT(0 != sk.typei);

	TEST_ASSERT_EQUAL(0,
			  make_mac(PAYLOAD, PAYLOAD_LEN, &sk, actual,
				   sizeof(actual)));
#else

	TEST_IGNORE_MESSAGE("OpenSSL not found, skipping...");

#endif	/* OPENSSL */
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
		"\tconst u_char EXPECTED_DIGEST[] = {",
		test_func);

	for (idx = 0; idx < octets; idx++) {
		if (0 == idx % 4) {
			dc += snprintf(dump + dc, sizeof(dump) - dc, "\n\t\t\t");
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
		dc += snprintf(dump + dc, sizeof(dump) - dc, "\n\t\t};");
	}

	msyslog(LOG_DEBUG, "%s", dump);
}

