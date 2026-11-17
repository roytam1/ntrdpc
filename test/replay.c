/*
 * replay.c - feeds recorded server packets to the ntrdpc core and checks the
 * picture it draws. It runs on Unix and on NT (nmake replay.exe), so the
 * core can be checked with each NT compiler and CPU.
 *
 *   replay in.bin out.bin    draw one case, write the picture
 *   replay -m cases.bin      draw many cases, compare each with its picture
 *
 * in.bin:    u32 width, u32 height, u32 bpp, then width x height u32 pixel
 *            values (top row first) as the starting picture, then server
 *            packets (TPKT) of an active session until the end of the file.
 * out.bin:   width x height u32 pixel values, top row first.
 * cases.bin: for each case: u32 length, an in.bin of that length, then
 *            width x height u32 pixel values: the expected picture.
 * All numbers are little-endian. Exit status 0 = every picture is right and
 * the client sent nothing (it sends a refresh when an order fails).
 * test/crosscheck.py makes these files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntrdpc.h"

static int sent, bad;

void ui_send(RDP *r, const u8 *d, int n) { (void)r; (void)d; (void)n; sent++; }
void ui_resize(RDP *r) { (void)r; }
void ui_palette(RDP *r) { (void)r; }
void ui_state(RDP *r) { (void)r; }
void ui_pointer_cached(RDP *r, int i) { (void)r; (void)i; }
void ui_pointer_system(RDP *r, int v) { (void)r; (void)v; }
void ui_random(RDP *r, u8 *b, int n) { (void)r; memset(b, 0, (size_t)n); }

void
ui_pointer_new(RDP *r, int i, int x, int y, const u8 *a, const u8 *c)
{
	(void)r; (void)i; (void)x; (void)y; (void)a; (void)c;
}

void
ui_invalidate(RDP *r, int x, int y, int w, int h)
{
	if (x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > r->fb.w ||
	    y + h > r->fb.h) {
		printf("bad invalidate %d,%d %dx%d\n", x, y, w, h);
		bad++;
	}
}

static u32
get32(const u8 *p)
{
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static u8 *
load(const char *name, long *size)
{
	FILE *fp;
	u8 *d;

	fp = fopen(name, "rb");
	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	*size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	d = (u8 *)malloc((size_t)*size + 1);
	if (d && fread(d, 1, (size_t)*size, fp) != (size_t)*size) {
		free(d);
		d = NULL;
	}
	fclose(fp);
	return d;
}

/* draws one in.bin; NULL if it is not one */
static RDP *
draw(const u8 *in, long size)
{
	RDPOPT opt;
	RDP *r;
	const u8 *p;
	int i, w, h, x, y, k;
	u32 v;

	if (size < 12)
		return NULL;
	w = (int)get32(in);
	h = (int)get32(in + 4);
	if (w < 1 || h < 1 || w > 4096 || h > 4096 ||
	    size < 12 + (long)w * h * 4)
		return NULL;
	memset(&opt, 0, sizeof(opt));
	opt.bpp = (int)get32(in + 8);
	r = rdp_new(&opt, NULL);
	if (!r)
		return NULL;
	if (!fb_alloc(&r->fb, w, h, opt.bpp)) {
		rdp_free(r);
		return NULL;
	}
	for (i = 0; i < 256; i++)
		r->fb.pal[i][0] = r->fb.pal[i][1] = r->fb.pal[i][2] = (u8)i;
	p = in + 12;
	for (y = 0; y < h; y++)
		for (x = 0; x < w; x++, p += 4) {
			v = get32(p);
			for (k = 0; k < r->fb.Bpp; k++)
				FB_ROW(&r->fb, y)[x * r->fb.Bpp + k] =
					(u8)(v >> (8 * k));
		}
	r->state = RS_ACTIVE;
	r->userid = 1004;
	r->shareid = 0x103EA;
	sent = bad = 0;
	rdp_recv(r, p, (int)(in + size - p));
	if (r->state != RS_ACTIVE) {
		printf("session ended: %s\n", r->err);
		bad++;
	}
	return r;
}

static u32
pixel(RDP *r, int x, int y)
{
	u32 v = 0;
	int k;

	for (k = 0; k < r->fb.Bpp; k++)
		v |= (u32)FB_ROW(&r->fb, y)[x * r->fb.Bpp + k] << (8 * k);
	return v;
}

static int
one(const char *inname, const char *outname)
{
	RDP *r;
	FILE *fp;
	u8 *in;
	long size;
	int x, y, k, ok;
	u32 v;

	in = load(inname, &size);
	if (!in) {
		printf("replay: cannot read %s\n", inname);
		return 2;
	}
	r = draw(in, size);
	if (!r) {
		printf("replay: %s is not a case\n", inname);
		return 2;
	}
	fp = fopen(outname, "wb");
	if (!fp)
		return 2;
	for (y = 0; y < r->fb.h; y++)
		for (x = 0; x < r->fb.w; x++) {
			v = pixel(r, x, y);
			for (k = 0; k < 4; k++)
				fputc((int)(v >> (8 * k) & 0xFF), fp);
		}
	fclose(fp);
	ok = !sent && !bad;
	rdp_free(r);
	free(in);
	return ok ? 0 : 1;
}

static int
many(const char *name)
{
	RDP *r;
	u8 *d;
	const u8 *p, *end, *want;
	long size, n;
	int count = 0, good = 0, diffs, x, y, fx = 0, fy = 0;
	u32 gv = 0, wv = 0;

	d = load(name, &size);
	if (!d) {
		printf("replay: cannot read %s\n", name);
		return 2;
	}
	p = d;
	end = d + size;
	while (end - p >= 4) {
		n = (long)get32(p);
		p += 4;
		if (n < 12 || n > end - p) {
			printf("replay: %s is broken at case %d\n", name, count);
			return 2;
		}
		r = draw(p, n);
		if (!r) {
			printf("replay: case %d is not a case\n", count);
			return 2;
		}
		want = p + n;
		if ((long)r->fb.w * r->fb.h * 4 > end - want) {
			printf("replay: case %d has no picture\n", count);
			return 2;
		}
		diffs = 0;
		for (y = 0; y < r->fb.h; y++)
			for (x = 0; x < r->fb.w; x++)
				if (pixel(r, x, y) !=
				    get32(want + ((long)y * r->fb.w + x) * 4)) {
					if (!diffs) {
						fx = x;
						fy = y;
						gv = pixel(r, x, y);
						wv = get32(want + ((long)y *
							r->fb.w + x) * 4);
					}
					diffs++;
				}
		if (diffs || sent || bad)
			printf("case %d (%d bpp): %d pixels differ "
			       "(first %d,%d: 0x%lX, want 0x%lX), "
			       "%d packets sent, %d errors\n",
			       count, r->fb.bpp, diffs, fx, fy,
			       (unsigned long)gv, (unsigned long)wv,
			       sent, bad);
		else
			good++;
		p = want + (long)r->fb.w * r->fb.h * 4;
		rdp_free(r);
		count++;
	}
	free(d);
	printf("replay: %d of %d cases right\n", good, count);
	return good == count && count ? 0 : 1;
}

int
main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "-m") == 0)
		return many(argv[2]);
	if (argc == 3)
		return one(argv[1], argv[2]);
	printf("usage: replay in.bin out.bin, or replay -m cases.bin\n");
	return 2;
}
