#include "config.h"

#include <string.h>

#include "unity.h"

#include "ntp.h"
#include "ntp_stdlib.h"
#include "recvbuff.h"
#include "ntp_refclock.h"

/*
 * Build the Zyfer refclock driver into this test translation unit,
 * but do not link libntpd to avoid duplicate symbols.
 */
#ifndef REFCLOCK
#define REFCLOCK 1
#endif
#ifndef CLOCK_ZYFER
#define CLOCK_ZYFER 1
#endif

/* ---- Minimal stubs for ntpd-only symbols used by refclock_zyfer.c ---- */

int refclock_open(const sockaddr_u *addr, const char *name, u_int speed, u_int ldisc);
int io_addclock(struct refclockio *rio);
void io_closeclock(struct refclockio *rio);
void refclock_report(struct peer *peer, int code);
void record_clock_stats(sockaddr_u *addr, const char *text);
void refclock_process_offset(struct refclockproc *pp, l_fp offset, l_fp lastrec, double fudgetime);
void refclock_receive(struct peer *peer);

void setUp(void);
void tearDown(void);
void test_fragmented_then_oversized_input_does_not_overflow(void);
void test_oversized_input_without_sync_is_ignored(void);

int
refclock_open(const sockaddr_u *addr, const char *name, u_int speed, u_int ldisc)
{
	(void)addr;
	(void)name;
	(void)speed;
	(void)ldisc;
	return 1;
}

int
io_addclock(struct refclockio *rio)
{
	(void)rio;
	return 1;
}

void
io_closeclock(struct refclockio *rio)
{
	(void)rio;
}
static int g_last_refclock_event;
static int g_refclock_receive_calls;

void
refclock_report(struct peer *peer, int code)
{
	(void)peer;
	g_last_refclock_event = code;
}

void
record_clock_stats(sockaddr_u *addr, const char *text)
{
	(void)addr;
	(void)text;
}

void
refclock_process_offset(struct refclockproc *pp, l_fp offset, l_fp lastrec, double fudgetime)
{
	(void)pp;
	(void)offset;
	(void)lastrec;
	(void)fudgetime;
}

void
refclock_receive(struct peer *peer)
{
	(void)peer;
	g_refclock_receive_calls++;
}

/* ---- Include the driver under test ---- */
#include "refclock_zyfer.c"

void
setUp(void)
{
	g_last_refclock_event = 0;
	g_refclock_receive_calls = 0;
}

void
tearDown(void)
{
}

static void
fill_recvbuf(struct recvbuf *rb, const void *data, size_t len)
{
	TEST_ASSERT_NOT_NULL(rb);
	TEST_ASSERT_TRUE(len <= sizeof(rb->recv_space));
	memset(&rb->recv_space, 0, sizeof(rb->recv_space));
	memcpy(&rb->recv_space, data, len);
	rb->recv_length = (int)len;
}

void
test_fragmented_then_oversized_input_does_not_overflow(void)
{
	static const char full_msg[] = "!TIME,2002,017,07,59,32,2,4,1";
	static const char frag1[] = "!TIME,2002";
	static const char frag2[] = ",017,07,59,32,2,4,1";

	struct peer peer;
	struct refclockproc pp;
	struct zyferunit unit;
	struct recvbuf rb;

	ZERO(peer);
	ZERO(pp);
	ZERO(unit);
	ZERO(rb);

	peer.procptr = &pp;
	pp.unitptr = &unit;
	rb.recv_peer = &peer;
	ZERO(rb.recv_time);

	/* First fragment seeds the in-progress frame. */
	fill_recvbuf(&rb, frag1, sizeof(frag1) - 1);
	zyfer_receive(&rb);
	TEST_ASSERT_EQUAL_INT((int)(sizeof(frag1) - 1), pp.lencode);
	TEST_ASSERT_EQUAL_INT((int)(sizeof(frag1) - 1), unit.Rcvptr);

	/* Second chunk finishes the frame, then contains lots of extra data. */
	char big_chunk[512];
	memset(big_chunk, 'Z', sizeof(big_chunk));
	memcpy(big_chunk, frag2, sizeof(frag2) - 1);

	unit.polled = 1;
	fill_recvbuf(&rb, big_chunk, sizeof(big_chunk));
	zyfer_receive(&rb);

	TEST_ASSERT_EQUAL_INT(LENZYFER, pp.lencode);
	TEST_ASSERT_EQUAL_STRING(full_msg, pp.a_lastcode);
	TEST_ASSERT_EQUAL_INT(0, unit.Rcvptr);
	TEST_ASSERT_EQUAL_INT(0, unit.polled);
	TEST_ASSERT_EQUAL_INT(1, g_refclock_receive_calls);
	TEST_ASSERT_EQUAL_INT(0, g_last_refclock_event);
}

void
test_oversized_input_without_sync_is_ignored(void)
{
	struct peer peer;
	struct refclockproc pp;
	struct zyferunit unit;
	struct recvbuf rb;
	char noise[400];

	memset(noise, 'A', sizeof(noise));
	ZERO(peer);
	ZERO(pp);
	ZERO(unit);
	ZERO(rb);

	peer.procptr = &pp;
	pp.unitptr = &unit;
	rb.recv_peer = &peer;
	ZERO(rb.recv_time);

	fill_recvbuf(&rb, noise, sizeof(noise));
	zyfer_receive(&rb);

	TEST_ASSERT_EQUAL_INT(0, pp.lencode);
	TEST_ASSERT_EQUAL_INT(0, unit.Rcvptr);
	TEST_ASSERT_EQUAL_INT(0, g_refclock_receive_calls);
}
