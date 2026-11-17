/*
 * orders.c - drawing orders and the caches behind them (MS-RDPEGDI): the
 * primary orders ntrdps sends (DstBlt, PatBlt, ScrBlt, MemBlt, LineTo,
 * OpaqueRect, SaveBitmap, MultiOpaqueRect, FastIndex, GlyphIndex) and the
 * secondary orders that fill the bitmap and glyph caches.
 */

#include <stdlib.h>
#include <string.h>
#include "ntrdpc.h"

/* wire order types */
#define O_DSTBLT	0x00
#define O_PATBLT	0x01
#define O_SCRBLT	0x02
#define O_LINETO	0x09
#define O_OPAQUERECT	0x0A
#define O_SAVEBITMAP	0x0B
#define O_MEMBLT	0x0D
#define O_MULTIOPAQUE	0x12
#define O_FASTINDEX	0x13
#define O_GLYPHINDEX	0x1B

/* controlFlags */
#define TS_STANDARD	0x01
#define TS_SECONDARY	0x02
#define TS_BOUNDS	0x04
#define TS_TYPE_CHANGE	0x08
#define TS_DELTA	0x10
#define TS_ZERO_BOUNDS	0x20

/* text flAccel bits */
#define SO_VERTICAL	0x04
#define SO_CHAR_INC_EQUAL_BM_BASE 0x20

#define NBMP		3
#define NGLYPH		10
#define SAVEPELS	230400L
#define MAXDELTA	512

static const int bmp_entries[NBMP] = { 600, 300, 262 };
static const int bmp_pixels[NBMP] = { 256, 1024, 4096 };
static const int glyph_entries[NGLYPH] = {
	254, 254, 254, 254, 254, 254, 254, 254, 254, 64
};
static const int glyph_cell[NGLYPH] = {
	4, 4, 8, 8, 16, 32, 64, 128, 256, 2048
};

/* the GDI hatch styles as 8 x 8 patterns, top row first */
static const u8 hatches[6][8] = {
	{ 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 },	/* - */
	{ 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 },	/* | */
	{ 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 },	/* \ */
	{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 },	/* / */
	{ 0x08, 0x08, 0x08, 0xFF, 0x08, 0x08, 0x08, 0x08 },	/* + */
	{ 0x81, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x81 }	/* x */
};

typedef struct {
	int w, h;
	u8 *data;			/* top-down rows of w pixels */
} CBMP;

typedef struct {
	int x, y, cx, cy;
	u8 *bits;
} CGLYPH;

typedef struct {
	int orgx, orgy, style, hatch;
	u8 extra[7];
} WBRUSH;

struct ORDSTATE {
	int type;			/* last primary order type */
	int bl, bt, br, bb;		/* bounds; right, bottom inclusive */

	struct {
		int x, y, w, h, rop;
	} dst;
	struct {
		int x, y, w, h, rop;
		u32 back, fore;
		WBRUSH brush;
	} pat;
	struct {
		int x, y, w, h, rop, sx, sy;
	} scr;
	struct {
		int mode, x1, y1, x2, y2;
		u32 back;
		int rop2, style, width;
		u32 color;
	} line;
	struct {
		int x, y, w, h;
		u32 color;
	} opaque;
	struct {
		u32 pos;
		int l, t, r, b, op;
	} save;
	struct {
		int cacheid, x, y, w, h, rop, sx, sy, index;
	} mem;
	struct {
		int x, y, w, h;
		u32 color;
		int n, len;
		u8 data[MAXDELTA];
	} multi;
	struct {
		int cacheid, fdrawing;
		u32 back, fore;
		int bkl, bkt, bkr, bkb, opl, opt, opr, opb, x, y;
		int len;
		u8 data[256];
	} fast;
	struct {
		int cacheid, flaccel, charinc, opred;
		u32 back, fore;
		int bkl, bkt, bkr, bkb, opl, opt, opr, opb;
		WBRUSH brush;
		int x, y;
		int len;
		u8 data[256];
	} glyph;

	CBMP *bmp[NBMP];
	int bmpBpp;			/* depth of the cached bitmaps */
	CGLYPH *glyphs[NGLYPH];
	u8 *savebuf;			/* SaveBitmap buffer */
	int saveBpp;
	int failed;			/* asked for a refresh after an error */
};


/*
 * Reading.
 */

typedef struct {
	const u8 *p, *end;
	int bad;
} RD;

static int
g8(RD *r)
{
	if (r->p >= r->end) {
		r->bad = 1;
		return 0;
	}
	return *r->p++;
}

static int
g16(RD *r)
{
	int v;

	if (r->end - r->p < 2) {
		r->bad = 1;
		r->p = r->end;
		return 0;
	}
	v = r->p[0] | r->p[1] << 8;
	r->p += 2;
	return v;
}

static int
gs16(RD *r)
{
	int v = g16(r);

	return v >= 0x8000 ? v - 0x10000 : v;
}

static u32
g32(RD *r)
{
	u32 v = (u32)g16(r);

	return v | (u32)g16(r) << 16;
}

static u32
gcolor(RD *r)
{
	u32 v = (u32)g8(r);

	v |= (u32)g8(r) << 8;
	return v | (u32)g8(r) << 16;
}

static int
sx8(int v)
{
	return v >= 0x80 ? v - 0x100 : v;
}

static void
coord(RD *r, int *v, int delta)
{
	if (delta)
		*v += sx8(g8(r));
	else
		*v = gs16(r);
}

static void
gbytes(RD *r, u8 *dst, int n)
{
	if (r->end - r->p < n) {
		r->bad = 1;
		r->p = r->end;
		return;
	}
	memcpy(dst, r->p, (size_t)n);
	r->p += n;
}

static int
le16(const u8 *p)
{
	return p[0] | p[1] << 8;
}


/*
 * Caches.
 */

ORDSTATE *
orders_new(void)
{
	ORDSTATE *o = (ORDSTATE *)malloc(sizeof(ORDSTATE));
	int i;

	if (!o)
		return NULL;
	memset(o, 0, sizeof(ORDSTATE));
	for (i = 0; i < NBMP; i++) {
		o->bmp[i] = (CBMP *)calloc((size_t)bmp_entries[i], sizeof(CBMP));
		if (!o->bmp[i])
			goto fail;
	}
	for (i = 0; i < NGLYPH; i++) {
		o->glyphs[i] = (CGLYPH *)calloc((size_t)glyph_entries[i],
						sizeof(CGLYPH));
		if (!o->glyphs[i])
			goto fail;
	}
	orders_reset(o);
	return o;
fail:
	orders_free(o);
	return NULL;
}

static void
clear_bitmaps(ORDSTATE *o)
{
	int i, j;

	for (i = 0; i < NBMP; i++) {
		if (!o->bmp[i])
			continue;
		for (j = 0; j < bmp_entries[i]; j++) {
			if (o->bmp[i][j].data)
				free(o->bmp[i][j].data);
			o->bmp[i][j].data = NULL;
		}
	}
}

void
orders_free(ORDSTATE *o)
{
	int i, j;

	if (!o)
		return;
	clear_bitmaps(o);
	for (i = 0; i < NBMP; i++)
		if (o->bmp[i])
			free(o->bmp[i]);
	for (i = 0; i < NGLYPH; i++) {
		if (!o->glyphs[i])
			continue;
		for (j = 0; j < glyph_entries[i]; j++)
			if (o->glyphs[i][j].bits)
				free(o->glyphs[i][j].bits);
		free(o->glyphs[i]);
	}
	if (o->savebuf)
		free(o->savebuf);
	free(o);
}

/* at each Demand Active: the field values start over; the caches stay */
void
orders_reset(ORDSTATE *o)
{
	int bmpBpp = o->bmpBpp, saveBpp = o->saveBpp;
	CBMP *bmp[NBMP];
	CGLYPH *glyphs[NGLYPH];
	u8 *savebuf = o->savebuf;

	memcpy(bmp, o->bmp, sizeof(bmp));
	memcpy(glyphs, o->glyphs, sizeof(glyphs));
	memset(o, 0, sizeof(ORDSTATE));
	memcpy(o->bmp, bmp, sizeof(bmp));
	memcpy(o->glyphs, glyphs, sizeof(glyphs));
	o->bmpBpp = bmpBpp;
	o->saveBpp = saveBpp;
	o->savebuf = savebuf;
	o->type = O_PATBLT;
}

static void
put16(u8 **p, int v)
{
	(*p)[0] = (u8)v;
	(*p)[1] = (u8)(v >> 8);
	*p += 2;
}

static void
put32(u8 **p, u32 v)
{
	put16(p, (int)(v & 0xFFFF));
	put16(p, (int)(v >> 16));
}

static void
zero(u8 **p, int n)
{
	memset(*p, 0, (size_t)n);
	*p += n;
}

/* the capability sets about orders and caches: Order, Bitmap Cache, Color
   Table Cache, Glyph Cache, Brush.  Returns the bytes; adds to *count. */
int
orders_capsets(u8 *out, int Bpp, int *count)
{
	static const int support[] = { 0, 1, 2, 3, 8, 10, 11, 18, 19, 27 };
	u8 *p = out;
	int i;

	put16(&p, 3);			/* Order */
	put16(&p, 88);
	zero(&p, 16);			/* terminalDescriptor */
	put32(&p, 0);
	put16(&p, 1);			/* desktopSaveXGranularity */
	put16(&p, 20);			/* desktopSaveYGranularity */
	put16(&p, 0);
	put16(&p, 1);			/* maximumOrderLevel */
	put16(&p, 0);			/* numberFonts */
	put16(&p, 0x002A);		/* NEGOTIATE, ZEROBOUNDSDELTAS, COLORINDEX */
	memset(p, 0, 32);
	for (i = 0; i < (int)(sizeof(support) / sizeof(support[0])); i++)
		p[support[i]] = 1;
	p += 32;
	put16(&p, 0);			/* textFlags */
	put16(&p, 0);
	put32(&p, 0);
	put32(&p, (u32)SAVEPELS);	/* desktopSaveSize */
	zero(&p, 8);

	put16(&p, 4);			/* Bitmap Cache, revision 1 */
	put16(&p, 40);
	zero(&p, 24);
	for (i = 0; i < NBMP; i++) {
		put16(&p, bmp_entries[i]);
		put16(&p, bmp_pixels[i] * Bpp);
	}

	put16(&p, 10);			/* Color Table Cache */
	put16(&p, 8);
	put16(&p, 6);
	put16(&p, 0);

	put16(&p, 16);			/* Glyph Cache */
	put16(&p, 52);
	for (i = 0; i < NGLYPH; i++) {
		put16(&p, glyph_entries[i]);
		put16(&p, glyph_cell[i]);
	}
	put32(&p, 0);			/* FragCache: no fragments */
	put16(&p, 2);			/* GLYPH_SUPPORT_FULL */
	put16(&p, 0);

	put16(&p, 15);			/* Brush */
	put16(&p, 8);
	put32(&p, 0);			/* BRUSH_DEFAULT: no brush cache */

	*count += 5;
	return (int)(p - out);
}


/*
 * Drawing helpers.
 */

static void
dirty(RDP *r, const BOX *clip, int x, int y, int w, int h)
{
	if (fb_cut(clip, &x, &y, &w, &h, NULL, NULL))
		ui_invalidate(r, x, y, w, h);
}

static void
make_brush(RDP *r, RBRUSH *b, const WBRUSH *w, u32 back, u32 fore)
{
	int i;

	b->style = w->style;
	b->orgx = w->orgx;
	b->orgy = w->orgy;
	b->fore = fb_color(&r->fb, fore);
	b->back = fb_color(&r->fb, back);
	memset(b->rows, 0, sizeof(b->rows));
	if (w->style == 2) {
		/* hatch lines in the brush color (ForeColor) */
		memcpy(b->rows, hatches[w->hatch < 6 ? w->hatch : 0], 8);
		b->back = fb_color(&r->fb, fore);
		b->fore = fb_color(&r->fb, back);
		b->style = 3;
	} else if (w->style == 3) {
		for (i = 0; i < 7; i++)
			b->rows[i] = w->extra[6 - i];
		b->rows[7] = (u8)w->hatch;
	} else if (w->style != 1) {
		b->style = 0;		/* solid; also a cached brush */
	}
}

static void
read_brush(RD *rd, u32 fl, int first, WBRUSH *b)
{
	if (fl & (1UL << (first - 1)))
		b->orgx = g8(rd);
	if (fl & (1UL << first))
		b->orgy = g8(rd);
	if (fl & (1UL << (first + 1)))
		b->style = g8(rd);
	if (fl & (1UL << (first + 2)))
		b->hatch = g8(rd);
	if (fl & (1UL << (first + 3)))
		gbytes(rd, b->extra, 7);
}

static CGLYPH *
glyph(ORDSTATE *o, int cache, int index)
{
	CGLYPH *g;

	if (cache < 0 || cache >= NGLYPH || index >= glyph_entries[cache])
		return NULL;
	g = &o->glyphs[cache][index];
	return g->bits ? g : NULL;
}

/* the text orders: fill Op, then draw the glyphs; ops are exclusive */
static void
text(RDP *r, const BOX *clip, int cacheid, int flaccel, int charinc,
     u32 textcolor, u32 opcolor, int bkl, int bkt, int bkr, int bkb,
     int opl, int opt, int opr, int opb, int x, int y, const u8 *data,
     int len)
{
	FBUF *f = &r->fb;
	CGLYPH *g;
	u32 tc = fb_color(f, textcolor);
	int i, adv;

	if (opr > f->w)
		opr = f->w;
	if (opr > opl && opb > opt) {
		fb_fill(f, clip, opl, opt, opr - opl, opb - opt,
			fb_color(f, opcolor));
		dirty(r, clip, opl, opt, opr - opl, opb - opt);
	}
	for (i = 0; i < len;) {
		g = glyph(r->ord, cacheid, data[i]);
		if (data[i] >= 0xFE)
			break;		/* fragments: never announced */
		i++;
		if (charinc == 0 && !(flaccel & SO_CHAR_INC_EQUAL_BM_BASE) &&
		    i < len) {
			adv = data[i++];
			if (adv & 0x80) {
				if (i + 1 >= len)
					break;
				adv = data[i] | data[i + 1] << 8;
				i += 2;
			}
			if (flaccel & SO_VERTICAL)
				y += adv;
			else
				x += adv;
		}
		if (g) {
			fb_glyph(f, clip, x + g->x, y + g->y, g->cx, g->cy,
				 g->bits, tc);
			dirty(r, clip, x + g->x, y + g->y, g->cx, g->cy);
		}
		if (flaccel & SO_CHAR_INC_EQUAL_BM_BASE)
			x += g ? g->cx : 0;
		else if (charinc)
			x += charinc;
	}
	if (bkr > bkl && bkb > bkt)
		dirty(r, clip, bkl, bkt, bkr - bkl, bkb - bkt);
}

static int
delta(const u8 *d, int len, int *i)
{
	int b, v;

	if (*i >= len)
		return 0;
	b = d[(*i)++];
	if (b & 0x80) {
		if (*i >= len)
			return 0;
		v = (b & 0x7F) << 8 | d[(*i)++];
		if (v & 0x4000)
			v -= 0x8000;
	} else {
		v = b & 0x7F;
		if (v & 0x40)
			v -= 0x80;
	}
	return v;
}

static void
multi_opaque(RDP *r, const BOX *clip, u32 pixel, int n, const u8 *d, int len)
{
	int i = (n + 1) / 2, k, zb, left = 0, top = 0, w = 0, h = 0;

	if (i > len)
		return;
	for (k = 0; k < n && i <= len; k++) {
		zb = d[k / 2];
		zb = (k & 1) ? zb & 0x0F : zb >> 4;
		if (!(zb & 8))
			left += delta(d, len, &i);
		if (!(zb & 4))
			top += delta(d, len, &i);
		if (!(zb & 2))
			w = delta(d, len, &i);
		else if (k == 0)
			w = 0;
		if (!(zb & 1))
			h = delta(d, len, &i);
		else if (k == 0)
			h = 0;
		fb_fill(&r->fb, clip, left, top, w, h, pixel);
		dirty(r, clip, left, top, w, h);
	}
}


/*
 * Primary orders.
 */

static int
nfields(int type)
{
	switch (type) {
	case O_DSTBLT:
		return 5;
	case O_PATBLT:
		return 12;
	case O_SCRBLT:
		return 7;
	case O_LINETO:
		return 10;
	case O_OPAQUERECT:
		return 7;
	case O_SAVEBITMAP:
		return 6;
	case O_MEMBLT:
		return 9;
	case O_MULTIOPAQUE:
		return 9;
	case O_FASTINDEX:
		return 15;
	case O_GLYPHINDEX:
		return 22;
	}
	return 0;
}

#define F(n)	(fl & (1UL << ((n) - 1)))

static int
primary(RDP *r, ORDSTATE *o, RD *rd, int ctrl)
{
	FBUF *f = &r->fb;
	BOX clip, scr;
	RBRUSH br;
	CBMP *bm;
	int nf, nb, i, d = ctrl & TS_DELTA, x, y, w, h, op, opt, opr, opb;
	u32 fl = 0;

	if (ctrl & TS_TYPE_CHANGE)
		o->type = g8(rd);
	nf = nfields(o->type);
	if (!nf)
		return 0;
	nb = (nf + 8) / 8 - ((ctrl >> 6) & 3);
	for (i = 0; i < nb; i++)
		fl |= (u32)g8(rd) << (8 * i);

	fb_screen(f, &scr);
	clip = scr;
	if (ctrl & TS_BOUNDS) {
		if (!(ctrl & TS_ZERO_BOUNDS)) {
			i = g8(rd);
			if (i & 0x01)
				o->bl = gs16(rd);
			else if (i & 0x10)
				o->bl += sx8(g8(rd));
			if (i & 0x02)
				o->bt = gs16(rd);
			else if (i & 0x20)
				o->bt += sx8(g8(rd));
			if (i & 0x04)
				o->br = gs16(rd);
			else if (i & 0x40)
				o->br += sx8(g8(rd));
			if (i & 0x08)
				o->bb = gs16(rd);
			else if (i & 0x80)
				o->bb += sx8(g8(rd));
		}
		clip.l = o->bl > 0 ? o->bl : 0;
		clip.t = o->bt > 0 ? o->bt : 0;
		clip.r = o->br + 1 < scr.r ? o->br + 1 : scr.r;
		clip.b = o->bb + 1 < scr.b ? o->bb + 1 : scr.b;
	}

	switch (o->type) {
	case O_DSTBLT:
		if (F(1)) coord(rd, &o->dst.x, d);
		if (F(2)) coord(rd, &o->dst.y, d);
		if (F(3)) coord(rd, &o->dst.w, d);
		if (F(4)) coord(rd, &o->dst.h, d);
		if (F(5)) o->dst.rop = g8(rd);
		if (rd->bad)
			return 0;
		fb_patblt(f, &clip, o->dst.x, o->dst.y, o->dst.w, o->dst.h,
			  o->dst.rop, NULL);
		dirty(r, &clip, o->dst.x, o->dst.y, o->dst.w, o->dst.h);
		break;

	case O_PATBLT:
		if (F(1)) coord(rd, &o->pat.x, d);
		if (F(2)) coord(rd, &o->pat.y, d);
		if (F(3)) coord(rd, &o->pat.w, d);
		if (F(4)) coord(rd, &o->pat.h, d);
		if (F(5)) o->pat.rop = g8(rd);
		if (F(6)) o->pat.back = gcolor(rd);
		if (F(7)) o->pat.fore = gcolor(rd);
		read_brush(rd, fl, 8, &o->pat.brush);
		if (rd->bad)
			return 0;
		make_brush(r, &br, &o->pat.brush, o->pat.back, o->pat.fore);
		fb_patblt(f, &clip, o->pat.x, o->pat.y, o->pat.w, o->pat.h,
			  o->pat.rop, &br);
		dirty(r, &clip, o->pat.x, o->pat.y, o->pat.w, o->pat.h);
		break;

	case O_SCRBLT:
		if (F(1)) coord(rd, &o->scr.x, d);
		if (F(2)) coord(rd, &o->scr.y, d);
		if (F(3)) coord(rd, &o->scr.w, d);
		if (F(4)) coord(rd, &o->scr.h, d);
		if (F(5)) o->scr.rop = g8(rd);
		if (F(6)) coord(rd, &o->scr.sx, d);
		if (F(7)) coord(rd, &o->scr.sy, d);
		if (rd->bad)
			return 0;
		fb_scrblt(f, &clip, o->scr.x, o->scr.y, o->scr.w, o->scr.h,
			  o->scr.sx, o->scr.sy, o->scr.rop);
		dirty(r, &clip, o->scr.x, o->scr.y, o->scr.w, o->scr.h);
		break;

	case O_LINETO:
		if (F(1)) o->line.mode = g16(rd);
		if (F(2)) coord(rd, &o->line.x1, d);
		if (F(3)) coord(rd, &o->line.y1, d);
		if (F(4)) coord(rd, &o->line.x2, d);
		if (F(5)) coord(rd, &o->line.y2, d);
		if (F(6)) o->line.back = gcolor(rd);
		if (F(7)) o->line.rop2 = g8(rd);
		if (F(8)) o->line.style = g8(rd);
		if (F(9)) o->line.width = g8(rd);
		if (F(10)) o->line.color = gcolor(rd);
		if (rd->bad)
			return 0;
		fb_line(f, &clip, o->line.x1, o->line.y1, o->line.x2,
			o->line.y2, o->line.rop2, fb_color(f, o->line.color));
		x = o->line.x1 < o->line.x2 ? o->line.x1 : o->line.x2;
		y = o->line.y1 < o->line.y2 ? o->line.y1 : o->line.y2;
		w = (o->line.x1 < o->line.x2 ? o->line.x2 : o->line.x1) - x + 1;
		h = (o->line.y1 < o->line.y2 ? o->line.y2 : o->line.y1) - y + 1;
		dirty(r, &clip, x, y, w, h);
		break;

	case O_OPAQUERECT:
		if (F(1)) coord(rd, &o->opaque.x, d);
		if (F(2)) coord(rd, &o->opaque.y, d);
		if (F(3)) coord(rd, &o->opaque.w, d);
		if (F(4)) coord(rd, &o->opaque.h, d);
		if (F(5))
			o->opaque.color = (o->opaque.color & 0xFFFF00) |
				(u32)g8(rd);
		if (F(6))
			o->opaque.color = (o->opaque.color & 0xFF00FF) |
				(u32)g8(rd) << 8;
		if (F(7))
			o->opaque.color = (o->opaque.color & 0x00FFFF) |
				(u32)g8(rd) << 16;
		if (rd->bad)
			return 0;
		fb_fill(f, &clip, o->opaque.x, o->opaque.y, o->opaque.w,
			o->opaque.h, fb_color(f, o->opaque.color));
		dirty(r, &clip, o->opaque.x, o->opaque.y, o->opaque.w,
		      o->opaque.h);
		break;

	case O_SAVEBITMAP:
		if (F(1)) o->save.pos = g32(rd);
		if (F(2)) coord(rd, &o->save.l, d);
		if (F(3)) coord(rd, &o->save.t, d);
		if (F(4)) coord(rd, &o->save.r, d);
		if (F(5)) coord(rd, &o->save.b, d);
		if (F(6)) o->save.op = g8(rd);
		if (rd->bad)
			return 0;
		if (!o->savebuf || o->saveBpp != f->Bpp) {
			if (o->savebuf)
				free(o->savebuf);
			o->savebuf = (u8 *)malloc((size_t)(SAVEPELS * f->Bpp));
			o->saveBpp = f->Bpp;
			if (!o->savebuf)
				break;
		}
		w = o->save.r - o->save.l + 1;
		h = o->save.b - o->save.t + 1;
		fb_save(f, o->savebuf, SAVEPELS, (long)o->save.pos, o->save.l,
			o->save.t, w, h, o->save.op == 1);
		if (o->save.op == 1)
			dirty(r, &scr, o->save.l, o->save.t, w, h);
		break;

	case O_MEMBLT:
		if (F(1)) o->mem.cacheid = g16(rd);
		if (F(2)) coord(rd, &o->mem.x, d);
		if (F(3)) coord(rd, &o->mem.y, d);
		if (F(4)) coord(rd, &o->mem.w, d);
		if (F(5)) coord(rd, &o->mem.h, d);
		if (F(6)) o->mem.rop = g8(rd);
		if (F(7)) coord(rd, &o->mem.sx, d);
		if (F(8)) coord(rd, &o->mem.sy, d);
		if (F(9)) o->mem.index = g16(rd);
		if (rd->bad)
			return 0;
		i = o->mem.cacheid & 0xFF;
		if (i >= NBMP || o->mem.index >= bmp_entries[i])
			break;
		bm = &o->bmp[i][o->mem.index];
		if (!bm->data || o->bmpBpp != f->Bpp)
			break;
		fb_memblt(f, &clip, o->mem.x, o->mem.y, o->mem.w, o->mem.h,
			  bm->data, bm->w, bm->h, o->mem.sx, o->mem.sy,
			  o->mem.rop);
		dirty(r, &clip, o->mem.x, o->mem.y, o->mem.w, o->mem.h);
		break;

	case O_MULTIOPAQUE:
		if (F(1)) coord(rd, &o->multi.x, d);
		if (F(2)) coord(rd, &o->multi.y, d);
		if (F(3)) coord(rd, &o->multi.w, d);
		if (F(4)) coord(rd, &o->multi.h, d);
		if (F(5))
			o->multi.color = (o->multi.color & 0xFFFF00) |
				(u32)g8(rd);
		if (F(6))
			o->multi.color = (o->multi.color & 0xFF00FF) |
				(u32)g8(rd) << 8;
		if (F(7))
			o->multi.color = (o->multi.color & 0x00FFFF) |
				(u32)g8(rd) << 16;
		if (F(8)) o->multi.n = g8(rd);
		if (F(9)) {
			o->multi.len = g16(rd);
			if (o->multi.len > MAXDELTA)
				return 0;
			gbytes(rd, o->multi.data, o->multi.len);
		}
		if (rd->bad)
			return 0;
		multi_opaque(r, &clip, fb_color(f, o->multi.color),
			     o->multi.n, o->multi.data, o->multi.len);
		break;

	case O_FASTINDEX:
		if (F(1)) o->fast.cacheid = g8(rd);
		if (F(2)) o->fast.fdrawing = g16(rd);
		if (F(3)) o->fast.back = gcolor(rd);
		if (F(4)) o->fast.fore = gcolor(rd);
		if (F(5)) coord(rd, &o->fast.bkl, d);
		if (F(6)) coord(rd, &o->fast.bkt, d);
		if (F(7)) coord(rd, &o->fast.bkr, d);
		if (F(8)) coord(rd, &o->fast.bkb, d);
		if (F(9)) coord(rd, &o->fast.opl, d);
		if (F(10)) coord(rd, &o->fast.opt, d);
		if (F(11)) coord(rd, &o->fast.opr, d);
		if (F(12)) coord(rd, &o->fast.opb, d);
		if (F(13)) coord(rd, &o->fast.x, d);
		if (F(14)) coord(rd, &o->fast.y, d);
		if (F(15)) {
			o->fast.len = g8(rd);
			gbytes(rd, o->fast.data, o->fast.len);
		}
		if (rd->bad)
			return 0;
		op = o->fast.opl;
		opt = o->fast.opt;
		opr = o->fast.opr;
		opb = o->fast.opb;
		if (opb == -32768) {	/* OpTop holds flags: take sides of Bk */
			i = opt;
			opb = (i & 0x01) ? o->fast.bkb : 0;
			opr = (i & 0x02) ? o->fast.bkr : opr;
			opt = (i & 0x04) ? o->fast.bkt : 0;
			op = (i & 0x08) ? o->fast.bkl : op;
		}
		x = o->fast.x == -32768 ? o->fast.bkl : o->fast.x;
		y = o->fast.y == -32768 ? o->fast.bkt : o->fast.y;
		text(r, &clip, o->fast.cacheid, o->fast.fdrawing >> 8,
		     o->fast.fdrawing & 0xFF, o->fast.back, o->fast.fore,
		     o->fast.bkl, o->fast.bkt, o->fast.bkr, o->fast.bkb,
		     op, opt, opr, opb, x, y, o->fast.data, o->fast.len);
		break;

	case O_GLYPHINDEX:
		if (F(1)) o->glyph.cacheid = g8(rd);
		if (F(2)) o->glyph.flaccel = g8(rd);
		if (F(3)) o->glyph.charinc = g8(rd);
		if (F(4)) o->glyph.opred = g8(rd);
		if (F(5)) o->glyph.back = gcolor(rd);
		if (F(6)) o->glyph.fore = gcolor(rd);
		if (F(7)) o->glyph.bkl = gs16(rd);
		if (F(8)) o->glyph.bkt = gs16(rd);
		if (F(9)) o->glyph.bkr = gs16(rd);
		if (F(10)) o->glyph.bkb = gs16(rd);
		if (F(11)) o->glyph.opl = gs16(rd);
		if (F(12)) o->glyph.opt = gs16(rd);
		if (F(13)) o->glyph.opr = gs16(rd);
		if (F(14)) o->glyph.opb = gs16(rd);
		read_brush(rd, fl, 15, &o->glyph.brush);
		if (F(20)) o->glyph.x = gs16(rd);
		if (F(21)) o->glyph.y = gs16(rd);
		if (F(22)) {
			o->glyph.len = g8(rd);
			gbytes(rd, o->glyph.data, o->glyph.len);
		}
		if (rd->bad)
			return 0;
		if (o->glyph.opred)	/* Op is the same as Bk */
			text(r, &clip, o->glyph.cacheid, o->glyph.flaccel,
			     o->glyph.charinc, o->glyph.back, o->glyph.fore,
			     o->glyph.bkl, o->glyph.bkt, o->glyph.bkr,
			     o->glyph.bkb, o->glyph.bkl, o->glyph.bkt,
			     o->glyph.bkr, o->glyph.bkb, o->glyph.x,
			     o->glyph.y, o->glyph.data, o->glyph.len);
		else
			text(r, &clip, o->glyph.cacheid, o->glyph.flaccel,
			     o->glyph.charinc, o->glyph.back, o->glyph.fore,
			     o->glyph.bkl, o->glyph.bkt, o->glyph.bkr,
			     o->glyph.bkb, o->glyph.opl, o->glyph.opt,
			     o->glyph.opr, o->glyph.opb, o->glyph.x,
			     o->glyph.y, o->glyph.data, o->glyph.len);
		break;

	default:
		return 0;
	}
	return !rd->bad;
}


/*
 * Secondary orders: cache fills.
 */

static void
cache_bitmap(RDP *r, ORDSTATE *o, const u8 *b, int len, int extra,
	     int compressed)
{
	int id, w, h, bpp, size, index, j, rowbytes, srcrow;
	const u8 *data;
	u8 *tmp, *top;
	CBMP *e;

	if (len < 9)
		return;
	id = b[0];
	w = b[2];
	h = b[3];
	bpp = b[4];
	size = le16(b + 5);
	index = le16(b + 7);
	data = b + 9;
	if (size > len - 9 || id >= NBMP || index >= bmp_entries[id] ||
	    w == 0 || h == 0 || bpp != r->fb.bpp)
		return;
	if (o->bmpBpp != r->fb.Bpp) {
		clear_bitmaps(o);
		o->bmpBpp = r->fb.Bpp;
	}
	rowbytes = w * r->fb.Bpp;
	tmp = (u8 *)malloc((size_t)rowbytes * h);
	if (!tmp)
		return;
	if (compressed) {
		if (!(extra & 0x0400)) {	/* TS_CD_HEADER first */
			if (size < 8) {
				free(tmp);
				return;
			}
			data += 8;
			size -= 8;
		}
		if (!rle_decode(data, size, tmp, w, h, bpp)) {
			free(tmp);
			return;
		}
		srcrow = rowbytes;
	} else {
		srcrow = size / h;
		if (srcrow < rowbytes) {
			free(tmp);
			return;
		}
		for (j = 0; j < h; j++)
			memcpy(tmp + (long)j * rowbytes, data + (long)j * srcrow,
			       (size_t)rowbytes);
	}
	/* rows came bottom-up; keep them top-down */
	top = (u8 *)malloc((size_t)rowbytes * h);
	if (!top) {
		free(tmp);
		return;
	}
	for (j = 0; j < h; j++)
		memcpy(top + (long)j * rowbytes, tmp + (long)(h - 1 - j) * rowbytes,
		       (size_t)rowbytes);
	free(tmp);
	e = &o->bmp[id][index];
	if (e->data)
		free(e->data);
	e->data = top;
	e->w = w;
	e->h = h;
}

static void
cache_glyph(ORDSTATE *o, const u8 *b, int len, int extra)
{
	int id, n, k, index, cx, cy, size, bytes;
	const u8 *p = b + 2, *end = b + len;
	CGLYPH *g;

	if (len < 2 || (extra & 0x0020))	/* revision 2: not announced */
		return;
	id = b[0];
	n = b[1];
	if (id >= NGLYPH)
		return;
	for (k = 0; k < n; k++) {
		if (end - p < 10)
			return;
		index = le16(p);
		cx = le16(p + 6);
		cy = le16(p + 8);
		bytes = ((cx + 7) / 8) * cy;
		size = (bytes + 3) & ~3;
		if (end - p - 10 < bytes)
			return;
		if (index < glyph_entries[id]) {
			g = &o->glyphs[id][index];
			if (g->bits)
				free(g->bits);
			g->bits = (u8 *)malloc((size_t)(bytes > 0 ? bytes : 1));
			if (g->bits) {
				g->x = le16(p + 2);
				if (g->x >= 0x8000)
					g->x -= 0x10000;
				g->y = le16(p + 4);
				if (g->y >= 0x8000)
					g->y -= 0x10000;
				g->cx = cx;
				g->cy = cy;
				memcpy(g->bits, p + 10, (size_t)bytes);
			}
		}
		p += 10 + size;
	}
}

static int
secondary(RDP *r, ORDSTATE *o, RD *rd)
{
	int len, extra, type;
	const u8 *body;

	len = gs16(rd);
	extra = g16(rd);
	type = g8(rd);
	if (rd->bad || len + 7 < 0 || rd->end - rd->p < len + 7)
		return 0;
	body = rd->p;
	switch (type) {
	case 0:				/* Cache Bitmap, uncompressed */
		cache_bitmap(r, o, body, len + 7, extra, 0);
		break;
	case 2:				/* Cache Bitmap, compressed */
		cache_bitmap(r, o, body, len + 7, extra, 1);
		break;
	case 3:				/* Cache Glyph */
		cache_glyph(o, body, len + 7, extra);
		break;
	default:			/* color table and others: not needed */
		break;
	}
	rd->p = body + len + 7;
	return 1;
}

/* an Orders update: count orders in p[len] */
int
orders_process(RDP *r, const u8 *p, int len, int count)
{
	ORDSTATE *o = r->ord;
	RD rd;
	int ctrl, ok = 1;

	rd.p = p;
	rd.end = p + len;
	rd.bad = 0;
	while (count-- > 0 && rd.p < rd.end && ok) {
		ctrl = g8(&rd);
		if (!(ctrl & TS_STANDARD))
			ok = 0;		/* alternate secondary: not announced */
		else if (ctrl & TS_SECONDARY)
			ok = secondary(r, o, &rd);
		else
			ok = primary(r, o, &rd, ctrl);
	}
	if (!ok) {
		/* the rest of this update is lost: ask for the whole screen
		   again, but not over and over */
		if (!o->failed)
			rdp_refresh(r, 0, 0, r->fb.w, r->fb.h);
		o->failed = 1;
		return 0;
	}
	o->failed = 0;
	return 1;
}
