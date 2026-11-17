/*
 * draw.c - drawing into the frame buffer: fills, copies, brushes, lines,
 * glyphs and the save buffer of SaveBitmap.  Pixels keep the session's own
 * values, and ROPs work on them bit by bit, as GDI does on the console.
 */

#include <stdlib.h>
#include <string.h>
#include "ntrdpc.h"

static u32
pixmask(const FBUF *f)
{
	switch (f->bpp) {
	case 8:
		return 0xFF;
	case 15:
		return 0x7FFF;
	case 16:
		return 0xFFFF;
	}
	return 0xFFFFFF;
}

static u32
getpx(const u8 *p, int Bpp)
{
	if (Bpp == 1)
		return p[0];
	if (Bpp == 2)
		return p[0] | (u32)p[1] << 8;
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16;
}

static void
putpx(u8 *p, int Bpp, u32 v)
{
	p[0] = (u8)v;
	if (Bpp > 1) {
		p[1] = (u8)(v >> 8);
		if (Bpp > 2)
			p[2] = (u8)(v >> 16);
	}
}

/* ROP3: bit i of rop is the result for P = bit 2 of i, S = bit 1, D = bit 0 */
static u32
rop3(int rop, u32 p, u32 s, u32 d)
{
	u32 r = 0;

	if (rop & 0x01)
		r |= ~p & ~s & ~d;
	if (rop & 0x02)
		r |= ~p & ~s & d;
	if (rop & 0x04)
		r |= ~p & s & ~d;
	if (rop & 0x08)
		r |= ~p & s & d;
	if (rop & 0x10)
		r |= p & ~s & ~d;
	if (rop & 0x20)
		r |= p & ~s & d;
	if (rop & 0x40)
		r |= p & s & ~d;
	if (rop & 0x80)
		r |= p & s & d;
	return r;
}

/* ROP2 (R2_BLACK = 1 .. R2_WHITE = 16) as the ROP3 that uses P and D */
static int
rop2to3(int rop2)
{
	int c = (rop2 - 1) & 15;
	int i, r = 0;

	for (i = 0; i < 8; i++)
		if ((c >> ((((i >> 2) & 1) << 1) | (i & 1))) & 1)
			r |= 1 << i;
	return r;
}


int
fb_alloc(FBUF *f, int w, int h, int bpp)
{
	int Bpp, stride;
	long size;
	u8 *bits;

	if (w < 1 || h < 1 || w > 4096 || h > 4096)
		return 0;
	Bpp = bpp == 8 ? 1 : bpp == 24 ? 3 : 2;
	stride = (w * Bpp + 3) & ~3;
	size = (long)stride * h;
	bits = (u8 *)malloc((size_t)size);
	if (!bits)
		return 0;
	memset(bits, 0, (size_t)size);
	if (f->bits)
		free(f->bits);
	f->bits = bits;
	f->w = w;
	f->h = h;
	f->bpp = bpp;
	f->Bpp = Bpp;
	f->stride = stride;
	return 1;
}

void
fb_free(FBUF *f)
{
	if (f->bits)
		free(f->bits);
	f->bits = NULL;
	f->w = f->h = 0;
}

/* an order color (TS_COLOR, 3 bytes read little-endian) as a pixel */
u32
fb_color(const FBUF *f, u32 c)
{
	switch (f->bpp) {
	case 8:
		return c & 0xFF;
	case 15:
		return c & 0x7FFF;
	case 16:
		return c & 0xFFFF;
	}
	/* 24 bpp: the bytes are R, G, B; a pixel is B, G, R */
	return (c & 0xFF) << 16 | (c & 0xFF00) | (c >> 16 & 0xFF);
}

void
fb_screen(const FBUF *f, BOX *clip)
{
	clip->l = 0;
	clip->t = 0;
	clip->r = f->w;
	clip->b = f->h;
}

/* cut x, y, w, h down to the clip box; move sx, sy (if given) along */
int
fb_cut(const BOX *c, int *x, int *y, int *w, int *h, int *sx, int *sy)
{
	int d;

	if (*x < c->l) {
		d = c->l - *x;
		*x += d;
		*w -= d;
		if (sx)
			*sx += d;
	}
	if (*y < c->t) {
		d = c->t - *y;
		*y += d;
		*h -= d;
		if (sy)
			*sy += d;
	}
	if (*x + *w > c->r)
		*w = c->r - *x;
	if (*y + *h > c->b)
		*h = c->b - *y;
	return *w > 0 && *h > 0;
}

void
fb_fill(FBUF *f, const BOX *clip, int x, int y, int w, int h, u32 pixel)
{
	int i, j, Bpp = f->Bpp;
	u8 *row, *first = NULL;

	if (!fb_cut(clip, &x, &y, &w, &h, NULL, NULL))
		return;
	for (j = 0; j < h; j++) {
		row = FB_ROW(f, y + j) + x * Bpp;
		if (Bpp == 1) {
			memset(row, (int)(pixel & 0xFF), (size_t)w);
		} else if (!first) {
			for (i = 0; i < w; i++)
				putpx(row + i * Bpp, Bpp, pixel);
			first = row;
		} else {
			memcpy(row, first, (size_t)(w * Bpp));
		}
	}
}

/* PatBlt and DstBlt: a ROP3 of the pattern and the destination */
void
fb_patblt(FBUF *f, const BOX *clip, int x, int y, int w, int h, int rop,
	  const RBRUSH *br)
{
	int i, j, Bpp = f->Bpp;
	u32 mask = pixmask(f), p, d;
	u8 *row, bits;

	if (br && br->style == 1)
		return;				/* null brush */
	if (!fb_cut(clip, &x, &y, &w, &h, NULL, NULL))
		return;
	if (!br || br->style == 0) {
		p = br ? br->fore : 0;
		if (rop == 0xF0) {
			fb_fill(f, clip, x, y, w, h, p);
			return;
		}
		if (rop == 0x00 || rop == 0xFF) {
			fb_fill(f, clip, x, y, w, h, rop ? mask : 0);
			return;
		}
		for (j = 0; j < h; j++) {
			row = FB_ROW(f, y + j) + x * Bpp;
			for (i = 0; i < w; i++, row += Bpp) {
				d = getpx(row, Bpp);
				putpx(row, Bpp, rop3(rop, p, 0, d) & mask);
			}
		}
		return;
	}
	for (j = 0; j < h; j++) {
		row = FB_ROW(f, y + j) + x * Bpp;
		bits = br->rows[(y + j - br->orgy) & 7];
		for (i = 0; i < w; i++, row += Bpp) {
			p = (bits & (0x80 >> ((x + i - br->orgx) & 7))) ?
				br->back : br->fore;
			if (rop == 0xF0) {
				putpx(row, Bpp, p);
			} else {
				d = getpx(row, Bpp);
				putpx(row, Bpp, rop3(rop, p, 0, d) & mask);
			}
		}
	}
}

/* ScrBlt: screen to screen; the areas may overlap */
void
fb_scrblt(FBUF *f, const BOX *clip, int x, int y, int w, int h, int sx,
	  int sy, int rop)
{
	BOX scr;
	int i, j, k, n, Bpp = f->Bpp;
	u32 mask = pixmask(f);
	u8 *tmp, *d;

	if (!fb_cut(clip, &x, &y, &w, &h, &sx, &sy))
		return;
	fb_screen(f, &scr);
	if (!fb_cut(&scr, &sx, &sy, &w, &h, &x, &y))
		return;
	n = w * Bpp;
	if (rop == 0xCC) {
		for (k = 0; k < h; k++) {
			j = sy < y ? h - 1 - k : k;
			memmove(FB_ROW(f, y + j) + x * Bpp,
				FB_ROW(f, sy + j) + sx * Bpp, (size_t)n);
		}
		return;
	}
	tmp = (u8 *)malloc((size_t)n);
	if (!tmp)
		return;
	for (k = 0; k < h; k++) {
		j = sy < y ? h - 1 - k : k;
		memcpy(tmp, FB_ROW(f, sy + j) + sx * Bpp, (size_t)n);
		d = FB_ROW(f, y + j) + x * Bpp;
		for (i = 0; i < w; i++, d += Bpp)
			putpx(d, Bpp, rop3(rop, 0, getpx(tmp + i * Bpp, Bpp),
					   getpx(d, Bpp)) & mask);
	}
	free(tmp);
}

/* MemBlt: from a cached bitmap; its rows go top-down, srcw pixels each */
void
fb_memblt(FBUF *f, const BOX *clip, int x, int y, int w, int h,
	  const u8 *src, int srcw, int srch, int sx, int sy, int rop)
{
	BOX sb;
	int i, j, Bpp = f->Bpp;
	u32 mask = pixmask(f);
	const u8 *s;
	u8 *d;

	if (!fb_cut(clip, &x, &y, &w, &h, &sx, &sy))
		return;
	sb.l = 0;
	sb.t = 0;
	sb.r = srcw;
	sb.b = srch;
	if (!fb_cut(&sb, &sx, &sy, &w, &h, &x, &y))
		return;
	for (j = 0; j < h; j++) {
		s = src + ((long)(sy + j) * srcw + sx) * Bpp;
		d = FB_ROW(f, y + j) + x * Bpp;
		if (rop == 0xCC) {
			memcpy(d, s, (size_t)(w * Bpp));
			continue;
		}
		for (i = 0; i < w; i++, s += Bpp, d += Bpp)
			putpx(d, Bpp, rop3(rop, 0, getpx(s, Bpp),
					   getpx(d, Bpp)) & mask);
	}
}

/* a bitmap update: srch rows of srcw pixels, bottom row first; the top-left
   w x h of it goes to x, y */
void
fb_putbits(FBUF *f, int x, int y, int w, int h, const u8 *src, int srcw,
	   int srch)
{
	BOX scr;
	int j, sx = 0, sy = 0, Bpp = f->Bpp;

	if (w > srcw)
		w = srcw;
	if (h > srch)
		h = srch;
	fb_screen(f, &scr);
	if (!fb_cut(&scr, &x, &y, &w, &h, &sx, &sy))
		return;
	for (j = 0; j < h; j++)
		memcpy(FB_ROW(f, y + j) + x * Bpp,
		       src + ((long)(srch - 1 - (sy + j)) * srcw + sx) * Bpp,
		       (size_t)(w * Bpp));
}

static void
plot(FBUF *f, const BOX *c, int x, int y, int rop, u32 pixel, u32 mask)
{
	u8 *p;

	if (x < c->l || x >= c->r || y < c->t || y >= c->b)
		return;
	p = FB_ROW(f, y) + x * f->Bpp;
	if (rop == 0xF0)
		putpx(p, f->Bpp, pixel);
	else
		putpx(p, f->Bpp, rop3(rop, pixel, 0, getpx(p, f->Bpp)) & mask);
}

/* LineTo: from x1, y1 up to x2, y2, without the end point, as GDI does */
void
fb_line(FBUF *f, const BOX *clip, int x1, int y1, int x2, int y2, int rop2,
	u32 pixel)
{
	int dx, dy, sx, sy, e, i, rop;
	u32 mask = pixmask(f);

	rop = rop2to3(rop2);
	if (rop == 0xAA)
		return;				/* R2_NOP */
	dx = x2 > x1 ? x2 - x1 : x1 - x2;
	dy = y2 > y1 ? y2 - y1 : y1 - y2;
	sx = x2 > x1 ? 1 : -1;
	sy = y2 > y1 ? 1 : -1;
	if (dx >= dy) {
		e = 2 * dy - dx;
		for (i = 0; i < dx; i++) {
			plot(f, clip, x1, y1, rop, pixel, mask);
			if (e > 0) {
				y1 += sy;
				e -= 2 * dx;
			}
			e += 2 * dy;
			x1 += sx;
		}
	} else {
		e = 2 * dx - dy;
		for (i = 0; i < dy; i++) {
			plot(f, clip, x1, y1, rop, pixel, mask);
			if (e > 0) {
				x1 += sx;
				e -= 2 * dy;
			}
			e += 2 * dx;
			y1 += sy;
		}
	}
}

/* a glyph: cy rows top-down, (cx + 7) / 8 bytes each, bit 7 = left pixel */
void
fb_glyph(FBUF *f, const BOX *c, int x, int y, int cx, int cy, const u8 *bits,
	 u32 pixel)
{
	int i, j, px, py, stride = (cx + 7) / 8, Bpp = f->Bpp;
	const u8 *src;
	u8 *row;

	for (j = 0; j < cy; j++) {
		py = y + j;
		if (py < c->t || py >= c->b)
			continue;
		row = FB_ROW(f, py);
		src = bits + j * stride;
		for (i = 0; i < cx; i++) {
			px = x + i;
			if (px < c->l || px >= c->r)
				continue;
			if (src[i >> 3] & (0x80 >> (i & 7)))
				putpx(row + px * Bpp, Bpp, pixel);
		}
	}
}

/* SaveBitmap: the w x h pixels at x, y go to (or come back from) the save
   buffer at pel pos, row after row */
void
fb_save(FBUF *f, u8 *buf, long bufpels, long pos, int x, int y, int w, int h,
	int restore)
{
	int j, i0, i1, Bpp = f->Bpp;
	u8 *s, *d;

	if (!buf || w <= 0 || h <= 0 || pos < 0 ||
	    pos + (long)w * h > bufpels)
		return;
	i0 = x < 0 ? -x : 0;
	i1 = x + w > f->w ? f->w - x : w;
	if (i1 <= i0)
		return;
	for (j = 0; j < h; j++) {
		if (y + j < 0 || y + j >= f->h)
			continue;
		s = buf + (pos + (long)j * w + i0) * Bpp;
		d = FB_ROW(f, y + j) + (x + i0) * Bpp;
		if (restore)
			memcpy(d, s, (size_t)((i1 - i0) * Bpp));
		else
			memcpy(s, d, (size_t)((i1 - i0) * Bpp));
	}
}
