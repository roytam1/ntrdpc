/*
 * mppc.c - the MPPC bulk decompressor (RDP 4.0 8K and RDP 5.0 64K types),
 * MS-RDPBCGR 3.1.8.  One history for the whole connection.
 */

#include <stdlib.h>
#include <string.h>
#include "ntrdpc.h"

#define PACKET_COMPRESSED	0x20
#define PACKET_AT_FRONT		0x40
#define PACKET_FLUSHED		0x80

struct MPPC {
	u8 hist[65536];
	long pos;
};

MPPC *
mppc_new(void)
{
	MPPC *m = (MPPC *)malloc(sizeof(MPPC));

	if (m) {
		memset(m->hist, 0, sizeof(m->hist));
		m->pos = 0;
	}
	return m;
}

void
mppc_free(MPPC *m)
{
	if (m)
		free(m);
}

/* the next 32 bits at bit pos, MSB first; zeros after the end */
static u32
peek32(const u8 *in, long bits, long pos)
{
	u32 v = 0;
	long b;
	int k;

	for (k = 0; k < 32; k++) {
		b = pos + k;
		v <<= 1;
		if (b < bits)
			v |= (in[b >> 3] >> (7 - (b & 7))) & 1;
	}
	return v;
}

/* flags: generalCompressedType of the PDU.  0 = error. */
int
mppc_expand(MPPC *m, const u8 *in, int len, int flags, const u8 **out,
	    int *outlen)
{
	long bits = (long)len * 8, pos = 0, hp, start, size, off, n, src;
	int big, ones, k;
	u32 a;

	*out = in;
	*outlen = len;
	if (!(flags & 0xE0))
		return 1;
	big = (flags & 0x0F) == 1;
	size = big ? 65536L : 8192L;
	if (flags & (PACKET_AT_FRONT | PACKET_FLUSHED))
		m->pos = 0;
	if (flags & PACKET_FLUSHED)
		memset(m->hist, 0, sizeof(m->hist));
	if (!(flags & PACKET_COMPRESSED))
		return 1;

	hp = start = m->pos;
	while (bits - pos >= 8) {
		a = peek32(in, bits, pos);
		if (hp >= size)
			return 0;
		if ((a & 0x80000000UL) == 0) {
			m->hist[hp++] = (u8)(a >> 24 & 0x7F);
			pos += 8;
			continue;
		}
		if ((a & 0xC0000000UL) == 0x80000000UL) {
			m->hist[hp++] = (u8)((a >> 23 & 0x7F) + 0x80);
			pos += 9;
			continue;
		}
		if (big) {
			if ((a & 0xF8000000UL) == 0xF8000000UL) {
				off = a >> 21 & 0x3F;
				pos += 11;
			} else if ((a & 0xF8000000UL) == 0xF0000000UL) {
				off = (a >> 19 & 0xFF) + 64;
				pos += 13;
			} else if ((a & 0xF0000000UL) == 0xE0000000UL) {
				off = (a >> 17 & 0x7FF) + 320;
				pos += 15;
			} else {
				off = (a >> 13 & 0xFFFF) + 2368;
				pos += 19;
			}
		} else {
			if ((a & 0xF0000000UL) == 0xF0000000UL) {
				off = a >> 22 & 0x3F;
				pos += 10;
			} else if ((a & 0xF0000000UL) == 0xE0000000UL) {
				off = (a >> 20 & 0xFF) + 64;
				pos += 12;
			} else {
				off = (a >> 16 & 0x1FFF) + 320;
				pos += 16;
			}
		}
		a = peek32(in, bits, pos);
		if ((a & 0x80000000UL) == 0) {
			n = 3;
			pos += 1;
		} else {
			ones = 0;
			while (ones < 32 && (a >> (31 - ones) & 1))
				ones++;
			if (ones > (big ? 14 : 11))
				return 0;
			k = ones + 1;
			n = (1L << k) + (long)(a >> (31 - ones - k) & ((1UL << k) - 1));
			pos += ones + 1 + k;
		}
		if (hp + n > size)
			return 0;
		src = (hp - off) & (size - 1);
		if (src + n > size)
			return 0;
		while (n-- > 0)
			m->hist[hp++] = m->hist[src++];
	}
	m->pos = hp;
	*out = m->hist + start;
	*outlen = (int)(hp - start);
	return 1;
}
