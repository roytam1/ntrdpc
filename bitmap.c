/*
 * bitmap.c - the interleaved RLE of bitmap updates and Cache Bitmap orders
 * (MS-RDPBCGR 2.2.9.1.1.3.1.2.4).  The stream starts with the bottom row.
 * "Above" below means the row decoded before: one row further up the stream.
 */

#include <string.h>
#include "ntrdpc.h"

/* order codes */
#define BG_RUN		0x0
#define FG_RUN		0x1
#define FGBG_IMAGE	0x2
#define COLOR_RUN	0x3
#define COLOR_IMAGE	0x4
#define SET_FG_RUN	0xC
#define SET_FGBG_IMAGE	0xD
#define DITHER_RUN	0xE
#define MEGA_BG_RUN	0xF0
#define MEGA_FG_RUN	0xF1
#define MEGA_FGBG_IMAGE	0xF2
#define MEGA_COLOR_RUN	0xF3
#define MEGA_COLOR_IMAGE 0xF4
#define MEGA_SET_FG_RUN	0xF6
#define MEGA_SET_FGBG	0xF7
#define MEGA_DITHER_RUN	0xF8
#define SPECIAL_FGBG_1	0xF9
#define SPECIAL_FGBG_2	0xFA
#define WHITE		0xFD
#define BLACK		0xFE

typedef struct {
	const u8 *in, *end;
	u8 *out, *start, *stop;
	int Bpp;
	long row;			/* bytes in a row */
	int first;			/* still in the first row */
	u32 fg;
	int bad;
} RLE;

static u32
rd(RLE *s)
{
	u32 v;

	if (s->end - s->in < s->Bpp) {
		s->bad = 1;
		return 0;
	}
	v = s->in[0];
	if (s->Bpp > 1)
		v |= (u32)s->in[1] << 8;
	if (s->Bpp > 2)
		v |= (u32)s->in[2] << 16;
	s->in += s->Bpp;
	return v;
}

static int
rd8(RLE *s)
{
	if (s->in >= s->end) {
		s->bad = 1;
		return 0;
	}
	return *s->in++;
}

static u32
above(RLE *s)
{
	const u8 *p = s->out - s->row;

	if (s->Bpp == 1)
		return p[0];
	if (s->Bpp == 2)
		return p[0] | (u32)p[1] << 8;
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16;
}

static void
wr(RLE *s, u32 v)
{
	if (s->stop - s->out < s->Bpp) {
		s->bad = 1;
		return;
	}
	s->out[0] = (u8)v;
	if (s->Bpp > 1)
		s->out[1] = (u8)(v >> 8);
	if (s->Bpp > 2)
		s->out[2] = (u8)(v >> 16);
	s->out += s->Bpp;
}

/* up to 8 pixels of a foreground / background image; bit 0 first */
static void
fgbg(RLE *s, int mask, int n)
{
	int i;

	for (i = 0; i < n && !s->bad; i++) {
		if (s->first)
			wr(s, (mask & (1 << i)) ? s->fg : 0);
		else
			wr(s, (mask & (1 << i)) ? above(s) ^ s->fg : above(s));
	}
}

int
rle_decode(const u8 *in, int len, u8 *out, int w, int h, int bpp)
{
	RLE s;
	int code, hdr, n, insert = 0;
	u32 a, b, white;

	s.Bpp = bpp == 8 ? 1 : bpp == 24 ? 3 : 2;
	s.in = in;
	s.end = in + len;
	s.out = s.start = out;
	s.row = (long)w * s.Bpp;
	s.stop = out + s.row * h;
	s.first = 1;
	s.bad = 0;
	white = bpp == 8 ? 0xFF : bpp == 15 ? 0x7FFF : bpp == 16 ? 0xFFFF :
		0xFFFFFF;
	s.fg = white;

	while (s.in < s.end && !s.bad) {
		if (s.first && s.out - s.start >= s.row) {
			s.first = 0;
			insert = 0;
		}
		hdr = *s.in++;
		if ((hdr & 0xC0) != 0xC0) {
			code = hdr >> 5;
			n = hdr & 0x1F;
			if (code == FGBG_IMAGE)
				n = n ? n * 8 : rd8(&s) + 1;
			else if (n == 0)
				n = rd8(&s) + 32;
		} else if ((hdr & 0xF0) == 0xF0) {
			code = hdr;
			n = 0;
			if (code < SPECIAL_FGBG_1) {
				n = rd8(&s);
				n |= rd8(&s) << 8;
			}
		} else {
			code = hdr >> 4;
			n = hdr & 0x0F;
			if (code == SET_FGBG_IMAGE)
				n = n ? n * 8 : rd8(&s) + 1;
			else if (n == 0)
				n = rd8(&s) + 16;
		}
		if (s.bad)
			break;

		if (code == BG_RUN || code == MEGA_BG_RUN) {
			if (insert && n > 0) {
				wr(&s, s.first ? s.fg : above(&s) ^ s.fg);
				n--;
			}
			while (n-- > 0 && !s.bad)
				wr(&s, s.first ? 0 : above(&s));
			insert = 1;
			continue;
		}
		insert = 0;

		switch (code) {
		case SET_FG_RUN:
		case MEGA_SET_FG_RUN:
			s.fg = rd(&s);
			/* fall through */
		case FG_RUN:
		case MEGA_FG_RUN:
			while (n-- > 0 && !s.bad)
				wr(&s, s.first ? s.fg : above(&s) ^ s.fg);
			break;
		case DITHER_RUN:
		case MEGA_DITHER_RUN:
			a = rd(&s);
			b = rd(&s);
			while (n-- > 0 && !s.bad) {
				wr(&s, a);
				wr(&s, b);
			}
			break;
		case COLOR_RUN:
		case MEGA_COLOR_RUN:
			a = rd(&s);
			while (n-- > 0 && !s.bad)
				wr(&s, a);
			break;
		case SET_FGBG_IMAGE:
		case MEGA_SET_FGBG:
			s.fg = rd(&s);
			/* fall through */
		case FGBG_IMAGE:
		case MEGA_FGBG_IMAGE:
			while (n > 0 && !s.bad) {
				fgbg(&s, rd8(&s), n > 8 ? 8 : n);
				n -= 8;
			}
			break;
		case COLOR_IMAGE:
		case MEGA_COLOR_IMAGE:
			while (n-- > 0 && !s.bad)
				wr(&s, rd(&s));
			break;
		case SPECIAL_FGBG_1:
			fgbg(&s, 0x03, 8);
			break;
		case SPECIAL_FGBG_2:
			fgbg(&s, 0x05, 8);
			break;
		case WHITE:
			wr(&s, white);
			break;
		case BLACK:
			wr(&s, 0);
			break;
		default:
			s.bad = 1;
			break;
		}
	}
	return !s.bad && s.out == s.stop;
}
