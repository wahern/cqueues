/* ==========================================================================
 * timer.c - Hierarchical timing wheel.
 * --------------------------------------------------------------------------
 * Copyright (c) 2013  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */

#include <limits.h>    /* CHAR_BIT */
#include <stddef.h>    /* NULL */
#include <stdint.h>    /* UINT64_C uint64_t */

#include <string.h>

#include <sys/queue.h>
#include <sys/param.h>

#include <stdio.h>
#define SAY_(fmt, ...) fprintf(stderr, fmt "%s", __FILE__, __LINE__, __func__, __VA_ARGS__);
#define SAY(...) SAY_("@@ %s:%d:%s: " __VA_ARGS__, "\n");
#define HAI SAY("HAI")

#define countof(a) (sizeof (a) / sizeof *(a))
#define endof(a) (&(a)[countof(a)])


#define CIRCLEQ_CONCAT(head1, head2, field) do {			\
	if (!CIRCLEQ_EMPTY(head2)) {					\
		if (!CIRCLEQ_EMPTY(head1)) {				\
			(head1)->cqh_last->field.cqe_next =		\
			    (head2)->cqh_first;				\
			(head2)->cqh_first->field.cqe_prev =		\
			    (head1)->cqh_last;				\
		} else {						\
			(head1)->cqh_first = (head2)->cqh_first;	\
			(head2)->cqh_first->field.cqe_prev =		\
			    (void *)(head1);				\
		}							\
		(head1)->cqh_last = (head2)->cqh_last;			\
		(head2)->cqh_last->field.cqe_next =			\
		    (void *)(head1);					\
		CIRCLEQ_INIT(head2);					\
	}								\
} while (0)



static inline uint64_t rotl(const uint64_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v << c) | (v >> (sizeof v * CHAR_BIT - c));
} /* rotl() */


static inline uint64_t rotr(const uint64_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v >> c) | (v << (sizeof v * CHAR_BIT - c));
} /* rotr() */


/*
 * From http://groups.google.com/group/comp.lang.c/msg/0cef41f343f0e875.
 *
 * The bitwise pattern 0x43147259a7abb7e can derive every permutation of 0
 * to 2^6-1, each permutation overlapping bitwise in the pattern, offset by
 * 1 bit. Multiplying by a power of 2 shifts one of the permutations into
 * the high 6 bits of the word, which is then shifted down 58 bits and
 * reduced modulo 2^6.
 *
 * The constant was found by brute force search with a sieve to quickly
 * discard invalid patterns. The following program generates constants for
 * mapping words of length 2^N (0 <= N <= 6), although it's not exhaustive.
 * Decode with `sed -e 's/^ \* //' | uudecode -p | gunzip -c`.
 *
 * begin 644 -
 * M'XL(`+J'&E$``\53VV[30!!]SG[%M%'3W=:T<5-%2$XL`4\(@9"@3S2*XAM=
 * MD:PC7Q"H[;]S=G;=NB$2[1-6K'CG<F;F[)FA-NFZS7*:U4VF37-V$]/Y"5V]
 * M__1U>KE\1RUL^&CHY%P,^[%KG=C8IT9=6IL%V%9(+.1$V40AAEE>:)/3QS=?
 * M/DB3Z*8.2"N24G:59*AH-B/G5(I>$0PCDEJI7O;G+GFS^JY3QK@6Y)\^.)`Y
 * M!/49@^(8MG"G1/>)&D+4S:K1*2W?EN6:RA^KWS(M3=T\4N!K.BN,Y++I5@P>
 * M8NH\-S2G<4`)FHR$&!1EA0X0K:T]PA]:X$9<.BRGIPPR2!"QP\??(^\$:!4A
 * M4Q<DN?2($H7SH,J;MC*HAP,[[N:4X'"/CKPOC,2]O2H>U=^3Y^!GJ3/4V[Z`
 * M`7M"QK?IY>+Y4Z,YF_.,(1>`T2\"]@H\I*,L.`RX-[U0%F+;-NG-JI+'U^98
 * M>1+LL'LX@.PRN7_\!VM1MB;[ARPV@65?\#TQ"L4TIM'(D>]Q.UW>]KH?_SHZ
 * M>\TOS6/"'-S-Y&+9J`XHILF%ZCN<\"-'[E-P:W37[[6P`8L.![NVNXQ^$+N*
 * M"-^CSDTWTX%,`,!,*$L^\^9P$18&SD5W=BNZ3E"<`Z#,,/J_K;`$.-!KP*E9
 * >&VE5P#?"7JPU?E-N_G'#O(`0[;+_`)GB4OE4!0``
 * `
 * end
 */
#define FFS64_HASH UINT64_C(0x43147259a7abb7e)
#define FFS64_MLEN 6
#define FFS64_INDEX(v) (((UINT64_C(1) << FFS64_MLEN) - 1) & ((((v) & -(v)) * FFS64_HASH) >> ((UINT64_C(1) << FFS64_MLEN) - FFS64_MLEN)))

static inline int ffs64(const uint64_t v) {
	static const int map[] = {
		63,  0,  1,  6,  2, 12,  7, 18,  3, 24, 13, 27,  8, 33, 19, 39,
		 4, 16, 25, 37, 14, 45, 28, 47,  9, 30, 34, 53, 20, 49, 40, 56,
		62,  5, 11, 17, 23, 26, 32, 38, 15, 36, 44, 46, 29, 52, 48, 55,
		61, 10, 22, 31, 35, 43, 51, 54, 60, 21, 42, 50, 59, 41, 58, 57,
	};

	return (v)? map[FFS64_INDEX(v)] + 1 : 0;
} /* ffs64() */


static inline int fls64(const uint64_t v) {
	return (v)? ((sizeof v * CHAR_BIT) - 1) - __builtin_clzll(v) : 0;
} /* fls64 */



CIRCLEQ_HEAD(timeouts, timeout);

#define TIMEOUT_INITIALIZER { 0, 0, { 0, 0 } }

struct timeout {
	uint64_t deadline;

	struct timeouts *pending;
	CIRCLEQ_ENTRY(timeout) cqe;
}; /* struct timeout */


#define PERIOD_BITS 6
#define PERIOD_INTS (1 << PERIOD_BITS)
#define PERIOD_MASK (PERIOD_INTS - 1)
#define DEADLINE_MASK ((UINT64_C(1) << (PERIOD_BITS * 4)) - 1)

#define TIMEOUT_PERIOD(time) (fls64(DEADLINE_MASK & time) / PERIOD_BITS)
#define TIMEOUT_MINUTE(period, time) (((time) >> ((period) * PERIOD_BITS)) & PERIOD_MASK)


struct timer {
	struct timeouts wheel[4][64], expired;

	uint64_t populated[4];
	uint64_t basetime;
}; /* struct timer */


struct timer *timer_init(struct timer *T) {
	unsigned i, j;

	for (i = 0; i < countof(T->wheel); i++) {
		for (j = 0; j < countof(T->wheel[i]); j++) {
			CIRCLEQ_INIT(&T->wheel[i][j]);
		}
	}

	CIRCLEQ_INIT(&T->expired);

	memset(&T->populated, 0, sizeof *T - offsetof(struct timer, populated));

	return T;
} /* timer_init() */


static inline uint64_t timer_rem(struct timer *T, struct timeout *to) {
	return to->deadline - T->basetime;
} /* timer_rem() */


void timer_del(struct timer *T, struct timeout *to) {
	if (to->pending) {
		CIRCLEQ_REMOVE(to->pending, to, cqe);

		if (to->pending != &T->expired && CIRCLEQ_EMPTY(to->pending)) {
			ptrdiff_t index = to->pending - &T->wheel[0][0];
			int period = index / 64;
			int minute = index % 64;

			T->populated[period] &= ~(UINT64_C(1) << minute);
		}

		to->pending = NULL;
	}
} /* timer_del() */


void timer_add(struct timer *T, struct timeout *to, uint64_t deadline) {
	uint64_t period, minute;

	timer_del(T, to);

	to->deadline = deadline;

	period = TIMEOUT_PERIOD(timer_rem(T, to));
	minute = TIMEOUT_MINUTE(period, deadline);

SAY("rem:%llu period:%llu (fls:%d) minute:%llu", timer_rem(T, to), period, fls64(timer_rem(T, to)), minute);

	to->pending = &T->wheel[period][minute];
	CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);

	T->populated[period] |= UINT64_C(1) << minute;
SAY("populated:0x%.8x%.8x", (int)(T->populated[period] >> 32), (int)(0xffffffff & T->populated[period]));
} /* timer_add() */


void timer_adj(struct timer *T, uint64_t abstime) {
	uint64_t elapsed, periods, period, i, j;
	uint64_t expired[4] = { 0, 0, 0, 0 };
	struct timeout *to;
	uint64_t step;

	elapsed = abstime - T->basetime;

	

	while (elapsed) {
		struct timeouts todo;

		CIRCLEQ_INIT(&todo);

		periods = TIMEOUT_PERIOD(elapsed) + 1;

SAY("elapsed:%llu periods:%llu", elapsed, periods);
		for (period = 0; period < periods; period++) {
			uint64_t base = TIMEOUT_MINUTE(period, T->basetime);
			uint64_t stop = TIMEOUT_MINUTE(period, T->basetime + elapsed);
SAY("populated[%llu]:0x%.8x%.8x", period, (int)(T->populated[period] >> 32), (int)(0xffffffff & T->populated[period]));
			uint64_t populated = rotr(T->populated[period], base);
			uint64_t count = PERIOD_MASK & (stop - base);
			uint64_t minute;

SAY("base:%llu stop:%llu period:%llu count:%llu", base, stop, period, count);
			populated &= (count)? (UINT64_C(1) << count) - 1 : ~UINT64_C(0);

			while ((minute = ffs64(populated))) {
				--minute;
				populated &= ~(UINT64_C(1) << minute);
				CIRCLEQ_CONCAT(&todo, &T->wheel[period][minute], cqe);
			}

			period++;
		}

		T->basetime += elapsed & DEADLINE_MASK;

		while (!CIRCLEQ_EMPTY(&todo)) {
			to = CIRCLEQ_FIRST(&todo);

			if (to->deadline > T->basetime) {
				to->pending = NULL;
				timer_add(T, to, to->deadline);
			} else {
				to->pending = &T->expired;
				CIRCLEQ_INSERT_TAIL(&T->expired, to, cqe);
			}
		}

		elapsed -= (elapsed & DEADLINE_MASK);
	}
} /* timer_adj() */




#include <stdio.h>

int main(void) {
	struct timer T;
	struct timeout to = TIMEOUT_INITIALIZER;
	uint64_t time = 0;

	timer_init(&T);
	timer_add(&T, &to, 234);

	while (CIRCLEQ_EMPTY(&T.expired) && time < 512) {
		time += 32;
		timer_adj(&T, time);
	}

	return 0;
} /* main() */

