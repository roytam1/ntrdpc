/*
 * window.c - the Windows part of ntrdpc: the main window, the socket, the
 * keyboard, the mouse and the pointer.  It uses only what Windows NT 3.1
 * has: Winsock 1.1 with WSAAsyncSelect, SetDIBitsToDevice, SetScrollRange.
 */

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntrdpc.h"
#include "ntwin.h"
#include "resource.h"

#ifndef WM_MOUSEWHEEL
#define WM_MOUSEWHEEL	0x020A		/* NT 4.0 only */
#endif
#ifndef SPI_GETWORKAREA
#define SPI_GETWORKAREA	48		/* NT 4.0 only; NT 3.x says no */
#endif
#ifndef INADDR_NONE
#define INADDR_NONE	0xFFFFFFFF
#endif
#ifndef KL_NAMELENGTH
#define KL_NAMELENGTH	9
#endif

#define WM_SOCKET	(WM_USER + 1)
#define WM_ENDED	(WM_USER + 2)
#define NETTIMER	1		/* net_poll, every 200 ms */
#define NCURSOR		32
#define MAXQUEUE	(4L * 1024 * 1024)
#define BANDROWS	32		/* rows per copy into memdc */
#define SQ(a)		((long)(a) * (a))

static const char appname[] = "ntrdpc";

static HINSTANCE hinst;
static HWND hwnd;
static int showcmd;
static CONFIG cfg;
static char hostname[256];
static int port;
static RDP *rdp;
static SOCKET sock = INVALID_SOCKET;
static int connected;			/* the TCP connection is up */
static int plain;			/* this server takes plain RDP only */
/* Win32s thunks Winsock down to 16-bit Win16, whose recv/send take a 16-bit
 * int length. 65536 truncates to 0, so recv() would return 0 ("server closed
 * the connection") without reading anything. Keep buffers under 32767. */
#define NETCHUNK 32767
static u8 rbuf[NETCHUNK];
static u8 *sendq;
static long sendlen, sendcap;
static int win32s;			/* running on Win32s, not NT */

/* the picture */
static BITMAPINFO *bmi;
static HPALETTE hpal;
static int paldev;			/* the display has a palette */
static HDC memdc;			/* the desktop in the screen's format */
static HBITMAP membm, oldbm;
static HPALETTE oldmpal;
static BOX stale;			/* desktop part memdc lacks */
static int isstale;
static u8 *lut;				/* 256-color screen: pixel -> color */
static int lutbpp;			/* the depth lut is for; 0: none */
static u8 *band;			/* rows of color numbers for memdc */
static BITMAPINFO *bmi8;		/* their header: DIB_PAL_COLORS */
static int scrollx, scrolly;		/* desktop pixel at client 0,0 */
static int offx, offy;			/* where a smaller desktop sits */
static RECT dirty;			/* changed, not invalidated yet */
static int isdirty;
static DWORD lastpaint;
static int full, minimized;
static int refit;			/* the desktop changed in full screen */
static RECT oldrect;
static LONG oldstyle;

/* input */
static u8 keydown[512];			/* scancode, + 256 for E0 keys */
static int buttons;
static int lastx = -1, lasty = -1;

/* the pointer */
static HCURSOR cursors[NCURSOR];
static HCURSOR cursor;			/* NULL: the arrow */
static int hidden;

static void session_start(void);


/*
 * The picture.
 */

static int
active(void)
{
	return rdp && rdp->state == RS_ACTIVE;
}

static void
title(const char *state)
{
	char buf[300];

	if (state)
		sprintf(buf, "%.200s - %s (%s)", hostname, appname, state);
	else
		sprintf(buf, "%.200s - %s", hostname, appname);
	SetWindowText(hwnd, buf);
}

/* Windows colors the 6 x 6 x 6 cube lacks: else teal shows as 009999 */
static const BYTE win[8][3] = {
	{ 0x80, 0, 0 }, { 0, 0x80, 0 }, { 0x80, 0x80, 0 },
	{ 0, 0, 0x80 }, { 0x80, 0, 0x80 }, { 0, 0x80, 0x80 },
	{ 0x80, 0x80, 0x80 }, { 0xC0, 0xC0, 0xC0 }
};

static void
make_palette(void)
{
	struct {
		WORD ver, n;
		PALETTEENTRY e[256];
	} lp;
	FBUF *f = &rdp->fb;
	int i;

	if (hpal)
		DeleteObject(hpal);
	hpal = NULL;
	if (!paldev)
		return;
	lp.ver = 0x300;
	lp.n = f->bpp == 8 ? 256 : 216 + 8;
	for (i = 0; i < (int)lp.n; i++) {
		if (f->bpp == 8) {
			lp.e[i].peRed = f->pal[i][0];
			lp.e[i].peGreen = f->pal[i][1];
			lp.e[i].peBlue = f->pal[i][2];
		} else if (i < 216) {	/* a 6 x 6 x 6 color cube */
			lp.e[i].peRed = (BYTE)(i / 36 * 51);
			lp.e[i].peGreen = (BYTE)(i / 6 % 6 * 51);
			lp.e[i].peBlue = (BYTE)(i % 6 * 51);
		} else {
			lp.e[i].peRed = win[i - 216][0];
			lp.e[i].peGreen = win[i - 216][1];
			lp.e[i].peBlue = win[i - 216][2];
		}
		lp.e[i].peFlags = 0;
	}
	hpal = CreatePalette((LOGPALETTE *)&lp);
}

static void
make_colors(void)
{
	FBUF *f = &rdp->fb;
	int i;

	for (i = 0; i < 256; i++) {
		bmi->bmiColors[i].rgbRed = f->pal[i][0];
		bmi->bmiColors[i].rgbGreen = f->pal[i][1];
		bmi->bmiColors[i].rgbBlue = f->pal[i][2];
		bmi->bmiColors[i].rgbReserved = 0;
	}
}

/*
 * A 256-color screen: the nearest of our 224 colors for each pixel value of
 * a 15 or 16 bit desktop, and for the top 5 bits of each color of 24 bits.
 * GDI would search the palette for every pixel of every paint: on NT 3.1
 * that took 2.8 s for a full 800 x 600 picture with many colors, this
 * table 6 ms (an Alpha, 2026-11-16).
 */
static void
make_lut(void)
{
	int bpp = rdp->fb.bpp, r, g, b, ri, gi, bi, i, k;
	long v, d, best;

	lutbpp = 0;
	if (!paldev || bpp == 8)
		return;
	if (!lut)
		lut = (u8 *)malloc(65536L);
	if (!lut)
		return;
	for (v = 0; v < 65536L; v++) {
		if (bpp == 16) {
			r = (int)(v >> 11) & 31;
			g = (int)(v >> 5) & 63;
			g = g << 2 | g >> 4;
		} else {
			r = (int)(v >> 10) & 31;
			g = (int)(v >> 5) & 31;
			g = g << 3 | g >> 2;
		}
		b = (int)v & 31;
		r = r << 3 | r >> 2;
		b = b << 3 | b >> 2;
		ri = (r + 25) / 51;
		gi = (g + 25) / 51;
		bi = (b + 25) / 51;
		k = ri * 36 + gi * 6 + bi;
		best = SQ(r - ri * 51) + SQ(g - gi * 51) + SQ(b - bi * 51);
		for (i = 0; i < 8; i++) {
			d = SQ(r - win[i][0]) + SQ(g - win[i][1]) +
			    SQ(b - win[i][2]);
			if (d < best) {
				best = d;
				k = 216 + i;
			}
		}
		lut[v] = (u8)k;
	}
	lutbpp = bpp;
}

static void
all_stale(void)
{
	stale.l = stale.t = 0;
	stale.r = rdp ? rdp->fb.w : 0;
	stale.b = rdp ? rdp->fb.h : 0;
	isstale = 1;
}

static void
free_store(void)
{
	if (memdc) {
		SelectObject(memdc, oldbm);
		if (oldmpal)
			SelectPalette(memdc, oldmpal, TRUE);
		DeleteDC(memdc);
	}
	if (membm)
		DeleteObject(membm);
	memdc = NULL;
	membm = NULL;
	oldmpal = NULL;
	isstale = 0;
	free(band);
	band = NULL;
}

/*
 * The desktop as a bitmap in the screen's own format. A paint is then one
 * BitBlt: 79 ms for 800 x 600 on that Alpha, against 156 ms for a DIB
 * straight to the screen. Without it (no memory), paint() uses the DIB.
 */
static void
make_store(void)
{
	FBUF *f = &rdp->fb;
	WORD *idx;
	HDC dc;
	int i;

	free_store();
	if (lutbpp) {
		band = (u8 *)malloc((size_t)((f->w + 3) & ~3) * BANDROWS);
		if (!bmi8)
			bmi8 = (BITMAPINFO *)malloc(sizeof(BITMAPINFOHEADER) +
						    256 * sizeof(WORD));
		if (bmi8) {
			memset(bmi8, 0, sizeof(BITMAPINFOHEADER));
			bmi8->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
			bmi8->bmiHeader.biPlanes = 1;
			bmi8->bmiHeader.biBitCount = 8;
			bmi8->bmiHeader.biCompression = BI_RGB;
			bmi8->bmiHeader.biClrUsed = 224;
			idx = (WORD *)bmi8->bmiColors;
			for (i = 0; i < 224; i++)
				idx[i] = (WORD)i;
		}
	}
	/* Win32s' GDI mis-converts an 8bpp DIB into a 16-color compatible
	 * bitmap: the result is stripes/noise. Draw to the screen directly. */
	if (win32s)
		return;
	dc = GetDC(hwnd);
	memdc = CreateCompatibleDC(dc);
	if (memdc)
		membm = CreateCompatibleBitmap(dc, f->w, f->h);
	ReleaseDC(hwnd, dc);
	if (!membm) {
		if (memdc)
			DeleteDC(memdc);
		memdc = NULL;
		return;
	}
	oldbm = (HBITMAP)SelectObject(memdc, membm);
	if (hpal) {
		oldmpal = SelectPalette(memdc, hpal, FALSE);
		RealizePalette(memdc);
	}
	all_stale();
}

/* copies a desktop box from the frame buffer into memdc */
static void
refresh(BOX bx)
{
	FBUF *f = &rdp->fb;
	const unsigned short *s16;
	const u8 *s;
	u8 *d;
	int w, n, x, y, y0, s8;

	if (bx.l < 0)
		bx.l = 0;
	if (bx.t < 0)
		bx.t = 0;
	if (bx.r > f->w)
		bx.r = f->w;
	if (bx.b > f->h)
		bx.b = f->h;
	w = bx.r - bx.l;
	if (w <= 0 || bx.b <= bx.t)
		return;
	if (!lutbpp || lutbpp != f->bpp || !band || !bmi8) {
		/* GDI converts, memory to memory; the rows go bottom-up */
		SetDIBitsToDevice(memdc, bx.l, bx.t, w, bx.b - bx.t, bx.l,
				  f->h - bx.b, 0, f->h, f->bits, bmi,
				  DIB_RGB_COLORS);
		return;
	}
	s8 = (w + 3) & ~3;
	bmi8->bmiHeader.biWidth = w;
	for (y0 = bx.t; y0 < bx.b; y0 += n) {
		n = bx.b - y0 < BANDROWS ? bx.b - y0 : BANDROWS;
		for (y = 0; y < n; y++) {	/* bottom-up: the top row last */
			s = FB_ROW(f, y0 + y) + bx.l * f->Bpp;
			d = band + (long)(n - 1 - y) * s8;
			if (f->bpp == 24) {
				for (x = 0; x < w; x++, s += 3)
					d[x] = lut[(s[2] >> 3) << 10 |
						   (s[1] >> 3) << 5 | s[0] >> 3];
			} else {
				s16 = (const unsigned short *)s;
				for (x = 0; x < w; x++)
					d[x] = lut[s16[x]];
			}
		}
		bmi8->bmiHeader.biHeight = n;
		bmi8->bmiHeader.biSizeImage = (DWORD)s8 * n;
		SetDIBitsToDevice(memdc, bx.l, y0, w, n, 0, 0, 0, n, band,
				  bmi8, DIB_PAL_COLORS);
	}
}

/* the DIB header for the frame buffer */
static void
make_bmi(void)
{
	FBUF *f = &rdp->fb;
	DWORD *mask;

	free_store();
	if (!bmi)
		bmi = (BITMAPINFO *)malloc(sizeof(BITMAPINFOHEADER) +
					   256 * sizeof(RGBQUAD));
	if (!bmi)
		return;
	memset(bmi, 0, sizeof(BITMAPINFOHEADER) + 256 * sizeof(RGBQUAD));
	bmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmi->bmiHeader.biWidth = f->w;
	bmi->bmiHeader.biHeight = f->h;		/* bottom-up */
	bmi->bmiHeader.biPlanes = 1;
	bmi->bmiHeader.biBitCount = (WORD)(f->Bpp * 8);
	bmi->bmiHeader.biCompression = BI_RGB;	/* 16 bits: RGB555 */
	bmi->bmiHeader.biSizeImage = (DWORD)f->stride * f->h;
	if (f->bpp == 8) {
		bmi->bmiHeader.biClrUsed = 256;
		make_colors();
	} else if (f->bpp == 16) {
		bmi->bmiHeader.biCompression = BI_BITFIELDS;
		mask = (DWORD *)bmi->bmiColors;
		mask[0] = 0xF800;
		mask[1] = 0x07E0;
		mask[2] = 0x001F;
	}
	make_palette();
	make_lut();
	make_store();
}

/* scroll bars and the place of the desktop in the window */
static void
layout(void)
{
	static int busy;
	RECT rc;
	LONG style;
	int cw, ch, fw = 0, fh = 0, sw, sh, mx, my, needx, needy;

	if (busy)
		return;
	busy = 1;
	if (rdp && rdp->fb.bits) {
		fw = rdp->fb.w;
		fh = rdp->fb.h;
	}
	/* start from the client without scroll bars: else they never go */
	GetClientRect(hwnd, &rc);
	style = GetWindowLong(hwnd, GWL_STYLE);
	sw = GetSystemMetrics(SM_CXVSCROLL);
	sh = GetSystemMetrics(SM_CYHSCROLL);
	cw = rc.right + (style & WS_VSCROLL ? sw : 0);
	ch = rc.bottom + (style & WS_HSCROLL ? sh : 0);
	needx = fw > cw;
	needy = fh > ch;
	if (needx && !needy)		/* a scroll bar makes the client smaller */
		needy = fh > ch - sh;
	if (needy && !needx)
		needx = fw > cw - sw;
	if (needy)
		cw -= sw;
	if (needx)
		ch -= sh;
	mx = needx ? fw - cw : 0;
	my = needy ? fh - ch : 0;
	if (scrollx > mx)
		scrollx = mx;
	if (scrolly > my)
		scrolly = my;
	SetScrollRange(hwnd, SB_HORZ, 0, mx, FALSE);
	SetScrollPos(hwnd, SB_HORZ, scrollx, TRUE);
	SetScrollRange(hwnd, SB_VERT, 0, my, FALSE);
	SetScrollPos(hwnd, SB_VERT, scrolly, TRUE);
	GetClientRect(hwnd, &rc);
	cw = rc.right;
	ch = rc.bottom;
	offx = fw && fw < cw ? (cw - fw) / 2 : 0;
	offy = fh && fh < ch ? (ch - fh) / 2 : 0;
	busy = 0;
}

/* the window as big as the desktop, but on the screen */
static void
fit(void)
{
	RECT rc, work;
	int w, h, x, y;

	rc.left = rc.top = 0;
	rc.right = rdp->fb.w;
	rc.bottom = rdp->fb.h;
	AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
	w = rc.right - rc.left;
	h = rc.bottom - rc.top;
	if (!SystemParametersInfo(SPI_GETWORKAREA, 0, &work, 0)) {
		work.left = work.top = 0;
		work.right = GetSystemMetrics(SM_CXSCREEN);
		work.bottom = GetSystemMetrics(SM_CYSCREEN);
	}
	if (w > work.right - work.left)
		w = work.right - work.left;
	if (h > work.bottom - work.top)
		h = work.bottom - work.top;
	GetWindowRect(hwnd, &rc);
	x = rc.left;
	y = rc.top;
	if (x + w > work.right)
		x = work.right - w;
	if (y + h > work.bottom)
		y = work.bottom - h;
	if (x < work.left)
		x = work.left;
	if (y < work.top)
		y = work.top;
	SetWindowPos(hwnd, NULL, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
}

static void
fullscreen(int on)
{
	if (on == full)
		return;
	if (on) {
		GetWindowRect(hwnd, &oldrect);
		oldstyle = GetWindowLong(hwnd, GWL_STYLE);
		SetWindowLong(hwnd, GWL_STYLE,
			      (oldstyle & ~(WS_OVERLAPPEDWINDOW | WS_MAXIMIZE)) |
			      WS_POPUP);
		SetWindowPos(hwnd, HWND_TOP, 0, 0,
			     GetSystemMetrics(SM_CXSCREEN),
			     GetSystemMetrics(SM_CYSCREEN), SWP_FRAMECHANGED);
	} else {
		SetWindowLong(hwnd, GWL_STYLE, oldstyle);
		SetWindowPos(hwnd, NULL, oldrect.left, oldrect.top,
			     oldrect.right - oldrect.left,
			     oldrect.bottom - oldrect.top,
			     SWP_NOZORDER | SWP_FRAMECHANGED);
		if (refit && rdp && rdp->fb.bits && !IsZoomed(hwnd))
			fit();
		refit = 0;
	}
	full = on;
	layout();
	InvalidateRect(hwnd, NULL, FALSE);
}

static void
paint(HDC dc, const RECT *r)
{
	FBUF *f = rdp ? &rdp->fb : NULL;
	HPALETTE old = NULL;
	RECT d, rc;
	int x, y, w, h;
	char buf[300];

	if (f && f->bits && bmi) {
		d.left = offx - scrollx;
		d.top = offy - scrolly;
		d.right = d.left + f->w;
		d.bottom = d.top + f->h;
		x = r->left > d.left ? r->left : d.left;
		y = r->top > d.top ? r->top : d.top;
		w = (r->right < d.right ? r->right : d.right) - x;
		h = (r->bottom < d.bottom ? r->bottom : d.bottom) - y;
		if (hpal) {
			old = SelectPalette(dc, hpal, FALSE);
			RealizePalette(dc);
		}
		if (memdc) {
			if (isstale) {
				isstale = 0;
				refresh(stale);
			}
			if (w > 0 && h > 0)
				BitBlt(dc, x, y, w, h, memdc, x - d.left,
				       y - d.top, SRCCOPY);
		} else if (w > 0 && h > 0)
			/* rows go bottom-up: the source y counts from the
			   bottom */
			SetDIBitsToDevice(dc, x, y, w, h, x - d.left,
					  f->h - (y - d.top) - h, 0, f->h,
					  f->bits, bmi, DIB_RGB_COLORS);
		if (old)
			SelectPalette(dc, old, FALSE);
		ExcludeClipRect(dc, d.left, d.top, d.right, d.bottom);
		FillRect(dc, r, (HBRUSH)GetStockObject(BLACK_BRUSH));
		return;
	}
	FillRect(dc, r, (HBRUSH)GetStockObject(BLACK_BRUSH));
	if (rdp) {
		GetClientRect(hwnd, &rc);
		sprintf(buf, "Connecting to %.200s", hostname);
		SetTextColor(dc, RGB(255, 255, 255));
		SetBkMode(dc, TRANSPARENT);
		DrawText(dc, buf, -1, &rc,
			 DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}
}

static void
flush_dirty(void)
{
	if (isdirty)
		InvalidateRect(hwnd, &dirty, FALSE);
	isdirty = 0;
}

/*
 * After a burst of data: paint now and then, not only when idle. While
 * more data waits, paint less often: a slow computer then catches up
 * instead of painting pictures that are already old.
 */
static void
paint_now(void)
{
	RECT rc;
	u_long n = 0;
	DWORD gap = 50;

	flush_dirty();
	if (sock != INVALID_SOCKET && ioctlsocket(sock, FIONREAD, &n) == 0 &&
	    n > 0)
		gap = 300;
	if (GetUpdateRect(hwnd, &rc, FALSE) &&
	    GetTickCount() - lastpaint > gap)
		UpdateWindow(hwnd);
}

static void
scroll(int bar, int code, int pos)
{
	RECT rc;
	int *v = bar == SB_HORZ ? &scrollx : &scrolly;
	int old = *v, nv = *v, lo, hi, page;

	GetClientRect(hwnd, &rc);
	page = bar == SB_HORZ ? rc.right : rc.bottom;
	GetScrollRange(hwnd, bar, &lo, &hi);
	switch (code) {
	case SB_LINEUP:
		nv -= 16;
		break;
	case SB_LINEDOWN:
		nv += 16;
		break;
	case SB_PAGEUP:
		nv -= page;
		break;
	case SB_PAGEDOWN:
		nv += page;
		break;
	case SB_THUMBTRACK:
	case SB_THUMBPOSITION:
		nv = pos;
		break;
	case SB_TOP:
		nv = 0;
		break;
	case SB_BOTTOM:
		nv = hi;
		break;
	}
	if (nv > hi)
		nv = hi;
	if (nv < 0)
		nv = 0;
	if (nv == old)
		return;
	UpdateWindow(hwnd);		/* first paint what waits, at the old place */
	*v = nv;
	SetScrollPos(hwnd, bar, nv, TRUE);
	if (bar == SB_HORZ)
		ScrollWindow(hwnd, old - nv, 0, NULL, NULL);
	else
		ScrollWindow(hwnd, 0, old - nv, NULL, NULL);
	UpdateWindow(hwnd);
}

static LRESULT
realize(int background)
{
	HDC dc;
	HPALETTE old;
	UINT n;

	if (!hpal)
		return 0;
	dc = GetDC(hwnd);
	old = SelectPalette(dc, hpal, (BOOL)background);
	n = RealizePalette(dc);
	SelectPalette(dc, old, TRUE);
	ReleaseDC(hwnd, dc);
	if (n) {
		if (memdc)		/* its colors are the screen's numbers */
			all_stale();
		InvalidateRect(hwnd, NULL, FALSE);
	}
	return n != 0;
}


/*
 * What the core asks for.
 */

void
ui_resize(RDP *r)
{
	(void)r;
	make_bmi();
	scrollx = scrolly = 0;
	if (full)
		refit = 1;		/* fit() when full screen ends */
	else if (!IsZoomed(hwnd) && !IsIconic(hwnd))
		fit();
	layout();
	InvalidateRect(hwnd, NULL, FALSE);
}

void
ui_palette(RDP *r)
{
	if (bmi && r->fb.bits && r->fb.bpp == 8) {
		free_store();		/* it holds the old palette */
		make_colors();
		make_palette();
		make_store();
	}
	InvalidateRect(hwnd, NULL, FALSE);
}

/* nearby changes become one rectangle: fewer, simpler update regions */
void
ui_invalidate(RDP *r, int x, int y, int w, int h)
{
	RECT rc;

	(void)r;
	if (memdc) {
		if (!isstale) {
			stale.l = x;
			stale.t = y;
			stale.r = x + w;
			stale.b = y + h;
			isstale = 1;
		} else {
			if (x < stale.l)
				stale.l = x;
			if (y < stale.t)
				stale.t = y;
			if (x + w > stale.r)
				stale.r = x + w;
			if (y + h > stale.b)
				stale.b = y + h;
		}
	}
	rc.left = x + offx - scrollx;
	rc.top = y + offy - scrolly;
	rc.right = rc.left + w;
	rc.bottom = rc.top + h;
	if (isdirty) {
		if (rc.left <= dirty.right + 16 && rc.right >= dirty.left - 16 &&
		    rc.top <= dirty.bottom + 16 && rc.bottom >= dirty.top - 16) {
			UnionRect(&dirty, &dirty, &rc);
			return;
		}
		InvalidateRect(hwnd, &dirty, FALSE);
	}
	dirty = rc;
	isdirty = 1;
}

static int
toggles(void)
{
	int t = 0;

	if (GetKeyState(VK_SCROLL) & 1)
		t |= TOG_SCROLL;
	if (GetKeyState(VK_NUMLOCK) & 1)
		t |= TOG_NUM;
	if (GetKeyState(VK_CAPITAL) & 1)
		t |= TOG_CAPS;
	return t;
}

void
ui_state(RDP *r)
{
	switch (r->state) {
	case RS_ACTIVE:
		title(NULL);
		rdp_sync(r, toggles());
		break;
	case RS_DONE:
		PostMessage(hwnd, WM_ENDED, 0, 0);
		break;
	}
}

/*
 * Bytes hard to guess, for TLS, NLA and RC4: the clocks, the memory, the
 * pointer, the process; rdp_random hashes them.  NT 4.0 adds its own
 * random bytes (CryptGenRandom); NT 3.x has none.
 */
typedef BOOL (WINAPI *ACQUIRE)(DWORD *, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI *GENRANDOM)(DWORD, DWORD, BYTE *);

void
ui_random(RDP *r, u8 *buf, int len)
{
	static HINSTANCE adv;
	static DWORD prov;
	static GENRANDOM gen;
	ACQUIRE acq;
	struct {
		SYSTEMTIME st;
		LARGE_INTEGER pc[16];
		MEMORYSTATUS ms;
		POINT pt;
		DWORD tick, pid, tid, msgtime, msgpos;
		void *stack;
	} s;
	u8 *p, more[64];
	int i;

	memset(&s, 0, sizeof(s));
	GetSystemTime(&s.st);
	for (i = 0; i < 16; i++) {
		QueryPerformanceCounter(&s.pc[i]);
		Sleep(0);
	}
	s.ms.dwLength = sizeof(s.ms);
	GlobalMemoryStatus(&s.ms);
	GetCursorPos(&s.pt);
	s.tick = GetTickCount();
	s.pid = GetCurrentProcessId();
	s.tid = GetCurrentThreadId();
	s.msgtime = (DWORD)GetMessageTime();
	s.msgpos = GetMessagePos();
	s.stack = (void *)&s;
	memset(buf, 0, (size_t)len);
	p = (u8 *)&s;
	for (i = 0; i < (int)sizeof(s); i++)
		buf[i % len] ^= p[i];
	if (!adv) {
		adv = LoadLibrary("advapi32.dll");
		acq = adv ? (ACQUIRE)GetProcAddress(adv,
						    "CryptAcquireContextA") : NULL;
		if (acq && acq(&prov, NULL, NULL, 1, 0xF0000000))
			gen = (GENRANDOM)GetProcAddress(adv,
							"CryptGenRandom");
	}
	if (gen && gen(prov, sizeof(more), more))
		for (i = 0; i < (int)sizeof(more); i++)
			buf[i % len] ^= more[i];
	memset(&s, 0, sizeof(s));
	memset(more, 0, sizeof(more));
	(void)r;
}


/*
 * The pointer.
 */

static void
show_cursor(void)
{
	if (!active())
		SetCursor(LoadCursor(NULL, rdp && rdp->state != RS_DONE ?
				     IDC_WAIT : IDC_ARROW));
	else if (hidden)
		SetCursor(NULL);
	else
		SetCursor(cursor ? cursor : LoadCursor(NULL, IDC_ARROW));
}

/* a new pointer shows at once when the mouse is over the desktop */
static void
new_cursor(void)
{
	POINT p;
	RECT rc;

	GetCursorPos(&p);
	if (WindowFromPoint(p) != hwnd)
		return;
	ScreenToClient(hwnd, &p);
	GetClientRect(hwnd, &rc);
	if (PtInRect(&rc, p))
		show_cursor();
}

/* black and white only: a cursor of NT 3.1 has no colors */
static HCURSOR
make_cursor(int hx, int hy, const u8 *and, const u8 *rgb)
{
	int cx = GetSystemMetrics(SM_CXCURSOR);
	int cy = GetSystemMetrics(SM_CYCURSOR);
	int x, y, stride, o, bit, lum;
	const u8 *p;
	u8 *am, *xm;
	HCURSOR c;

	if (cx < 1 || cx > 64)
		cx = 32;
	if (cy < 1 || cy > 64)
		cy = 32;
	stride = (cx + 15) / 16 * 2;		/* rows are WORD aligned */
	am = (u8 *)malloc((size_t)stride * cy);
	xm = (u8 *)malloc((size_t)stride * cy);
	if (!am || !xm) {
		free(am);
		free(xm);
		return NULL;
	}
	memset(am, 0xFF, (size_t)stride * cy);
	memset(xm, 0, (size_t)stride * cy);
	for (y = 0; y < 32 && y < cy; y++)
		for (x = 0; x < 32 && x < cx; x++) {
			p = rgb + (y * 32 + x) * 3;
			lum = p[0] * 30 + p[1] * 59 + p[2] * 11;
			o = y * stride + x / 8;
			bit = 0x80 >> (x & 7);
			if (and[y * 4 + x / 8] & (0x80 >> (x & 7))) {
				if (lum)	/* screen XOR color: invert */
					xm[o] |= (u8)bit;
			} else {
				am[o] &= (u8)~bit;
				if (lum >= 12750)
					xm[o] |= (u8)bit;
			}
		}
	if (hx >= cx)
		hx = cx - 1;
	if (hy >= cy)
		hy = cy - 1;
	c = CreateCursor(hinst, hx, hy, cx, cy, am, xm);
	free(am);
	free(xm);
	return c;
}

void
ui_pointer_new(RDP *r, int index, int hotx, int hoty, const u8 *and,
	       const u8 *rgb)
{
	HCURSOR c = make_cursor(hotx, hoty, and, rgb), old = NULL;

	(void)r;
	if (index >= 0 && index < NCURSOR) {
		old = cursors[index];
		cursors[index] = c;
	}
	cursor = c;
	hidden = 0;
	new_cursor();
	if (old && old != c)
		DestroyCursor(old);
}

void
ui_pointer_cached(RDP *r, int index)
{
	(void)r;
	if (index >= 0 && index < NCURSOR && cursors[index]) {
		cursor = cursors[index];
		hidden = 0;
		new_cursor();
	}
}

void
ui_pointer_system(RDP *r, int visible)
{
	(void)r;
	if (visible)
		cursor = NULL;
	hidden = !visible;
	new_cursor();
}

static void
free_cursors(void)
{
	int i;

	SetCursor(LoadCursor(NULL, IDC_ARROW));
	for (i = 0; i < NCURSOR; i++) {
		if (cursors[i])
			DestroyCursor(cursors[i]);
		cursors[i] = NULL;
	}
	cursor = NULL;
	hidden = 0;
}


/*
 * Keyboard and mouse.
 */

static void
key(UINT msg, WPARAM vk, LPARAM lp)
{
	int sc = (int)(lp >> 16) & 0xFF;
	int ext = (lp & 0x01000000L) != 0;
	int up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
	int i, flags;

	if (vk == VK_PAUSE) {		/* E1 1D 45, all at once, as mstsc */
		if (!up) {
			rdp_key(rdp, RK_EXT1, 0x1D);
			rdp_key(rdp, 0, 0x45);
			rdp_key(rdp, RK_EXT1 | RK_UP, 0x1D);
			rdp_key(rdp, RK_UP, 0x45);
		}
		return;
	}
	if (vk == VK_NUMLOCK)
		ext = 0;		/* Windows marks it E0; RDP wants 45 */
	if (sc == 0)
		sc = (int)MapVirtualKey((UINT)vk, 0) & 0xFF;
	if (sc == 0)
		return;
	if (!up && GetKeyState(VK_CONTROL) < 0 && GetKeyState(VK_MENU) < 0) {
		if (vk == VK_RETURN) {		/* Ctrl+Alt+Enter */
			fullscreen(!full);
			return;
		}
		if (vk == VK_END) {		/* Ctrl+Alt+End: Ctrl+Alt+Del */
			rdp_key(rdp, RK_EXT, 0x53);
			rdp_key(rdp, RK_EXT | RK_UP | RK_DOWN, 0x53);
			return;
		}
	}
	i = sc | (ext ? 256 : 0);
	if (up) {
		if (!keydown[i]) {
			if (vk != VK_SNAPSHOT)
				return;
			/* Windows gives Print Screen as a key-up only */
			rdp_key(rdp, ext ? RK_EXT : 0, sc);
		}
		keydown[i] = 0;
		flags = RK_UP | RK_DOWN;
	} else {
		flags = keydown[i] ? RK_DOWN : 0;
		keydown[i] = 1;
	}
	rdp_key(rdp, flags | (ext ? RK_EXT : 0), sc);
}

static void
send_cad(void)
{
	if (!active())
		return;
	rdp_key(rdp, 0, 0x1D);
	rdp_key(rdp, 0, 0x38);
	rdp_key(rdp, RK_EXT, 0x53);
	rdp_key(rdp, RK_EXT | RK_UP | RK_DOWN, 0x53);
	rdp_key(rdp, RK_UP | RK_DOWN, 0x38);
	rdp_key(rdp, RK_UP | RK_DOWN, 0x1D);
}

/* lost the focus: let go of every key and button the server thinks held */
static void
release_all(void)
{
	int i;

	for (i = 0; i < 512; i++)
		if (keydown[i]) {
			keydown[i] = 0;
			if (active())
				rdp_key(rdp, RK_UP | RK_DOWN |
					(i & 256 ? RK_EXT : 0), i & 255);
		}
	if (active() && lastx >= 0) {
		if (buttons & RM_B1)
			rdp_mouse(rdp, RM_B1, lastx, lasty);
		if (buttons & RM_B2)
			rdp_mouse(rdp, RM_B2, lastx, lasty);
		if (buttons & RM_B3)
			rdp_mouse(rdp, RM_B3, lastx, lasty);
	}
	buttons = 0;
}

static void
mouse(int flags, LPARAM lp)
{
	int x, y;

	if (!active())
		return;
	x = (short)LOWORD(lp) - offx + scrollx;
	y = (short)HIWORD(lp) - offy + scrolly;
	if (x >= rdp->fb.w)
		x = rdp->fb.w - 1;
	if (y >= rdp->fb.h)
		y = rdp->fb.h - 1;
	if (x < 0)
		x = 0;
	if (y < 0)
		y = 0;
	if (flags == RM_MOVE && x == lastx && y == lasty)
		return;
	lastx = x;
	lasty = y;
	rdp_mouse(rdp, flags, x, y);
}

static void
button(int b, int down, WPARAM wp, LPARAM lp)
{
	if (down) {
		SetCapture(hwnd);
		buttons |= b;
		mouse(b | RM_DOWN, lp);
	} else {
		buttons &= ~b;
		mouse(b, lp);
		if (!(wp & (MK_LBUTTON | MK_RBUTTON | MK_MBUTTON)))
			ReleaseCapture();
	}
}

static void
wheel(int delta)
{
	if (!active())
		return;
	if (delta > 255)
		delta = 255;
	if (delta < -256)
		delta = -256;
	rdp_mouse(rdp, RM_WHEEL | (delta & 0x1FF), lastx < 0 ? 0 : lastx,
		  lasty < 0 ? 0 : lasty);
}


/*
 * The socket.
 * Win32s' 16-bit Winsock thunk reports "try again" in several ways: 0 or
 * SOCKET_ERROR with WSAEWOULDBLOCK, WSAEINPROGRESS or WSAEALREADY. Real NT
 * only uses SOCKET_ERROR/WSAEWOULDBLOCK. All mean "not now", not a failure.
 */
static int
net_transient(int err)
{
	return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS ||
	       err == WSAEALREADY;
}

void
ui_send(RDP *r, const u8 *d, int n)
{
	u8 *q;
	int k;

	if (sock == INVALID_SOCKET)
		return;
	while (sendlen == 0 && n > 0) {
		k = send(sock, (char *)d, n > NETCHUNK ? NETCHUNK : n, 0);
		if (k == SOCKET_ERROR) {
			if (net_transient(WSAGetLastError()))
				break;
			rdp_fail(r, "The connection broke.");
			return;
		}
		d += k;
		n -= k;
	}
	if (n <= 0)
		return;
	if (sendlen + n > sendcap) {
		if (sendlen + n > MAXQUEUE) {
			rdp_fail(r, "The server does not take data any more.");
			return;
		}
		q = (u8 *)realloc(sendq, (size_t)(sendlen + n + 65536L));
		if (!q) {
			rdp_fail(r, "Out of memory.");
			return;
		}
		sendq = q;
		sendcap = sendlen + n + 65536L;
	}
	memcpy(sendq + sendlen, d, (size_t)n);
	sendlen += n;
}

static void
flush_send(void)
{
	long done = 0;
	int k;

	while (done < sendlen) {
		long rem = sendlen - done;
		k = send(sock, (char *)sendq + done,
			 rem > NETCHUNK ? NETCHUNK : (int)rem, 0);
		if (k == SOCKET_ERROR) {
			if (!net_transient(WSAGetLastError()))
				rdp_fail(rdp, "The connection broke.");
			break;
		}
		done += k;
	}
	if (done) {
		memmove(sendq, sendq + done, (size_t)(sendlen - done));
		sendlen -= done;
	}
}

static void
connect_error(char *buf, int err)
{
	switch (err) {
	case WSAECONNREFUSED:
		sprintf(buf, "%.200s refused the connection.", hostname);
		break;
	case WSAETIMEDOUT:
		sprintf(buf, "%.200s did not answer.", hostname);
		break;
	case WSAENETUNREACH:
	case WSAEHOSTUNREACH:
		sprintf(buf, "Cannot reach %.200s.", hostname);
		break;
	default:
		sprintf(buf, "Cannot connect to %.200s (error %d).", hostname,
			err);
		break;
	}
}

static void
on_connect(int err)
{
	char buf[300];
	BOOL one = TRUE;

	if (connected)
		return;
	if (err) {
		connect_error(buf, err);
		rdp_fail(rdp, buf);
		return;
	}
	connected = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
	rdp_start(rdp);
}

/* reads what waits, up to 256 KB at a time */
static void
on_read(void)
{
	long total = 0;
	int n;

	while (rdp->state != RS_DONE && total < 262144L) {
		n = recv(sock, (char *)rbuf, sizeof(rbuf), 0);
		if (n > 0) {
			rdp_recv(rdp, rbuf, n);
			total += n;
			continue;
		}
		/* On NT 0 is a real close (the error may be stale). Win32s
		 * reports "no data" as 0 with WSAEWOULDBLOCK, so trust the
		 * error code there. */
		if (n == 0 && !win32s) {
			rdp_closed(rdp);
			break;
		}
		if (net_transient(WSAGetLastError()))
			break;
		rdp_closed(rdp);
		break;
	}
}

static void
on_close(void)
{
	int n;

	while (rdp->state != RS_DONE &&
	       (n = recv(sock, (char *)rbuf, sizeof(rbuf), 0)) > 0)
		rdp_recv(rdp, rbuf, n);
	if (rdp->state != RS_DONE &&
	    ((n == 0 && !win32s) || !net_transient(WSAGetLastError())))
		rdp_closed(rdp);
}

static void
net(WPARAM wp, LPARAM lp)
{
	if ((SOCKET)wp != sock || !rdp || rdp->state == RS_DONE)
		return;
	switch (WSAGETSELECTEVENT(lp)) {
	case FD_CONNECT:
		on_connect(WSAGETSELECTERROR(lp));
		break;
	case FD_READ:
		on_read();
		break;
	case FD_WRITE:
		flush_send();
		break;
	case FD_CLOSE:
		on_close();
		break;
	}
	paint_now();
}

/*
 * Every 200 ms. The Winsock of NT 3.1 loses socket messages: no FD_WRITE
 * after FD_CONNECT, and sometimes no FD_READ or FD_CLOSE. So look at the
 * socket here too, without waiting.
 */
static void
net_poll(void)
{
	fd_set rd, wr, ex;
	struct timeval tv;
	int err, len;

	if (sock == INVALID_SOCKET || !rdp || rdp->state == RS_DONE)
		return;
	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);
	if (!connected) {
		FD_SET(sock, &wr);
		FD_SET(sock, &ex);
	} else {
		FD_SET(sock, &rd);
		if (sendlen)
			FD_SET(sock, &wr);
	}
	tv.tv_sec = 0;
	/* A zero timeout keeps Win32s' 16-bit Winsock from ever calling its
	 * blocking hook, so the network stack never runs and the connect (and
	 * everything after it) hangs. A decent non-zero timeout lets select()
	 * pump the hook repeatedly; harmless on NT. */
	tv.tv_usec = 1000;
	/* On Win32s the 16-bit thunk misses readiness after the first packet,
	 * so skip select() and let recv()/send() below say "not now" instead.
	 * NT still uses select() as the fallback for lost socket messages. */
	if (!win32s)
		select(0, &rd, &wr, &ex, &tv);
	if (!connected) {
		if (win32s) {
			err = 0;
			len = sizeof(err);
			getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err,
				   &len);
			on_connect(err ? err : 0);
		} else if (FD_ISSET(sock, &ex)) {
			err = 0;
			len = sizeof(err);
			getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err,
				   &len);
			on_connect(err ? err : WSAECONNREFUSED);
		} else if (FD_ISSET(sock, &wr))
			on_connect(0);
	} else {
		if (sendlen)
			flush_send();
		if (rdp->state != RS_DONE)
			on_read();
	}
	paint_now();
}

static u32
layout_id(void)
{
	char name[KL_NAMELENGTH + 1];

	if (GetKeyboardLayoutName(name))
		return (u32)strtoul(name, NULL, 16);
	return 0x409;
}

static void
session_start(void)
{
	RDPOPT o;
	struct sockaddr_in sa;
	struct hostent *he;
	unsigned long a;
	char name[MAX_COMPUTERNAME_LENGTH + 1], buf[300], *colon;
	DWORD n;
	int cx = GetSystemMetrics(SM_CXSCREEN);
	int cy = GetSystemMetrics(SM_CYSCREEN);

	strncpy(hostname, cfg.host, sizeof(hostname) - 1);
	port = 3389;
	colon = strchr(hostname, ':');
	if (colon) {
		*colon = 0;
		port = atoi(colon + 1);
		if (port <= 0 || port > 65535)
			port = 3389;
	}
	memset(&o, 0, sizeof(o));
	strncpy(o.user, cfg.user, sizeof(o.user) - 1);
	strncpy(o.password, cfg.password, sizeof(o.password) - 1);
	strncpy(o.domain, cfg.domain, sizeof(o.domain) - 1);
	n = sizeof(name);
	if (!GetComputerName(name, &n))
		strcpy(name, "NTRDPC");
	strncpy(o.client, name, sizeof(o.client) - 1);
	o.width = cfg.width ? cfg.width : cfg.full ? cx : cx < 800 ? cx : 800;
	o.height = cfg.height ? cfg.height : cfg.full ? cy :
		   cy < 600 ? cy : 600;
	o.width &= ~3;
	o.bpp = cfg.bpp;
	o.compress = 1;
	o.perf = cfg.effects ? 0 : PERF_FAST;	/* less to send and draw */
	o.keylayout = layout_id();
	o.plain = plain;
	rdp = rdp_new(&o, NULL);
	memset(&o, 0, sizeof(o));
	if (!rdp) {
		MessageBox(NULL, "Out of memory.", appname, MB_OK | MB_ICONSTOP);
		DestroyWindow(hwnd);
		return;
	}

	title("connecting");
	scrollx = scrolly = 0;
	layout();
	ShowWindow(hwnd, showcmd);
	showcmd = SW_SHOW;
	if (cfg.full)
		fullscreen(1);
	InvalidateRect(hwnd, NULL, FALSE);
	UpdateWindow(hwnd);

	a = inet_addr(hostname);
	if (a == INADDR_NONE) {
		he = gethostbyname(hostname);
		if (!he) {
			sprintf(buf, "Cannot find the computer %.200s.",
				hostname);
			rdp_fail(rdp, buf);
			return;
		}
		memcpy(&a, he->h_addr, 4);
	}
	connected = 0;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		sprintf(buf, "Windows Sockets error %d.", WSAGetLastError());
		rdp_fail(rdp, buf);
		return;
	}
	if (win32s) {
		/* The Win32s 16-bit Winsock thunk's WSAAsyncSelect delivers
		 * readiness unreliably. net_poll() does all the polling, so
		 * just put the socket in non-blocking mode with FIONBIO. */
		u_long one = 1;
		if (ioctlsocket(sock, FIONBIO, &one) == SOCKET_ERROR) {
			sprintf(buf, "Windows Sockets error %d.",
				WSAGetLastError());
			rdp_fail(rdp, buf);
			return;
		}
	} else if (WSAAsyncSelect(sock, hwnd, WM_SOCKET, FD_CONNECT | FD_READ |
				   FD_WRITE | FD_CLOSE) == SOCKET_ERROR) {
		sprintf(buf, "Windows Sockets error %d.", WSAGetLastError());
		rdp_fail(rdp, buf);
		return;
	}
	SetTimer(hwnd, NETTIMER, 200, NULL);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((u_short)port);
	sa.sin_addr.s_addr = a;
	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
		if (!net_transient(WSAGetLastError())) {
			connect_error(buf, WSAGetLastError());
			rdp_fail(rdp, buf);
		}
	} else {
		/* Some Winsock 1.1 stacks (notably the Win32s thunk) complete
		 * connect() at once and may not send a reliable FD_CONNECT.
		 * Start the session here; a later FD_CONNECT is ignored by
		 * on_connect() because "connected" is already set. */
		on_connect(0);
	}
}

/* the session ended: the reason goes into the connect dialog */
static void
session_ended(void)
{
	char why[sizeof(rdp->err)];
	int again;

	if (!rdp)
		return;
	strcpy(why, rdp->err);
	again = rdp->again && !plain;
	KillTimer(hwnd, NETTIMER);
	if (sock != INVALID_SOCKET)
		closesocket(sock);
	sock = INVALID_SOCKET;
	connected = 0;
	rdp_free(rdp);
	rdp = NULL;
	sendlen = 0;
	isdirty = 0;
	memset(keydown, 0, sizeof(keydown));
	buttons = 0;
	lastx = lasty = -1;
	free_cursors();
	free_store();
	lutbpp = 0;
	if (hpal)
		DeleteObject(hpal);
	hpal = NULL;
	if (full)
		fullscreen(0);
	if (again) {			/* the server takes plain RDP only */
		plain = 1;
		session_start();
		return;
	}
	plain = 0;
	if (!why[0]) {			/* the user closed the window */
		DestroyWindow(hwnd);
		return;
	}
	ShowWindow(hwnd, SW_HIDE);
	if (!dlg_connect(hinst, &cfg, why)) {
		DestroyWindow(hwnd);
		return;
	}
	session_start();
}

static void
about(void)
{
	MessageBox(hwnd, "ntrdpc " NTRDPC_VERSION "\n"
		   "RDP client for Windows NT\n\n"
		   "Full screen: Ctrl+Alt+Enter\n"
		   "Ctrl+Alt+Del: Ctrl+Alt+End",
		   "About ntrdpc", MB_OK);
}


/*
 * The window.
 */

static LRESULT CALLBACK
wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
	PAINTSTRUCT ps;
	HDC dc;

	if (!hwnd)			/* messages from inside CreateWindow */
		hwnd = h;
	switch (msg) {
	case WM_PAINT:
		dc = BeginPaint(h, &ps);
		paint(dc, &ps.rcPaint);
		EndPaint(h, &ps);
		lastpaint = GetTickCount();
		return 0;
	case WM_ERASEBKGND:
		return 1;
	case WM_SIZE:
		if (wp == SIZE_MINIMIZED) {
			minimized = 1;
			if (rdp)
				rdp_suppress(rdp, 0);
			return 0;
		}
		if (minimized) {
			minimized = 0;
			if (rdp)
				rdp_suppress(rdp, 1);
		}
		layout();
		InvalidateRect(h, NULL, FALSE);
		return 0;
	case WM_HSCROLL:
		scroll(SB_HORZ, LOWORD(wp), (short)HIWORD(wp));
		return 0;
	case WM_VSCROLL:
		scroll(SB_VERT, LOWORD(wp), (short)HIWORD(wp));
		return 0;
	case WM_KEYDOWN:
	case WM_KEYUP:
	case WM_SYSKEYDOWN:
	case WM_SYSKEYUP:
		if (!active())
			break;
		key(msg, wp, lp);
		return 0;
	case WM_SETFOCUS:
		if (active())
			rdp_sync(rdp, toggles());
		break;
	case WM_KILLFOCUS:
		release_all();
		break;
	case WM_MOUSEMOVE:
		mouse(RM_MOVE, lp);
		return 0;
	case WM_LBUTTONDOWN:
		button(RM_B1, 1, wp, lp);
		return 0;
	case WM_LBUTTONUP:
		button(RM_B1, 0, wp, lp);
		return 0;
	case WM_RBUTTONDOWN:
		button(RM_B2, 1, wp, lp);
		return 0;
	case WM_RBUTTONUP:
		button(RM_B2, 0, wp, lp);
		return 0;
	case WM_MBUTTONDOWN:
		button(RM_B3, 1, wp, lp);
		return 0;
	case WM_MBUTTONUP:
		button(RM_B3, 0, wp, lp);
		return 0;
	case WM_MOUSEWHEEL:
		wheel((short)HIWORD(wp));
		return 0;
	case WM_SETCURSOR:
		if (LOWORD(lp) != HTCLIENT)
			break;
		show_cursor();
		return TRUE;
	case WM_QUERYNEWPALETTE:
		return realize(0);
	case WM_PALETTECHANGED:
		if ((HWND)wp != h)
			realize(1);
		return 0;
	case WM_SYSCOMMAND:
		switch (wp & 0xFFF0) {
		case IDM_CAD:
			send_cad();
			return 0;
		case IDM_FULL:
			fullscreen(!full);
			return 0;
		case IDM_ABOUT:
			about();
			return 0;
		}
		break;
	case WM_SOCKET:
		net(wp, lp);
		return 0;
	case WM_TIMER:
		if (wp == NETTIMER)
			net_poll();
		return 0;
	case WM_ENDED:
		session_ended();
		return 0;
	case WM_CLOSE:
		if (rdp && rdp->state != RS_DONE) {
			rdp_close(rdp);		/* then WM_ENDED */
			return 0;
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(h, msg, wp, lp);
}

int WINAPI
WinMain(HINSTANCE hi, HINSTANCE prev, LPSTR cmdline, int show)
{
	WNDCLASS wc;
	WSADATA wsa;
	MSG msg;
	HMENU m;
	HDC dc;
	DWORD dwWinVer;
	int r;

	(void)prev;
	dwWinVer = GetVersion();
    win32s = (dwWinVer >= 0x80000000) && ((dwWinVer & 0xFF) == 3);
	hinst = hi;
	showcmd = show;
	cfg_defaults(&cfg);
	cfg_load(&cfg);
	r = cfg_args(&cfg, cmdline);
	if (r < 0)
		return 1;
	if (r == 0 && !dlg_connect(hi, &cfg, NULL))
		return 0;
	if (WSAStartup(0x0101, &wsa) != 0) {
		MessageBox(NULL, "Windows Sockets do not work.", appname,
			   MB_OK | MB_ICONSTOP);
		return 1;
	}
	dc = GetDC(NULL);
	paldev = (GetDeviceCaps(dc, RASTERCAPS) & RC_PALETTE) != 0;
	ReleaseDC(NULL, dc);

	memset(&wc, 0, sizeof(wc));
	wc.lpfnWndProc = wndproc;
	wc.hInstance = hi;
	wc.hIcon = LoadIcon(hi, MAKEINTRESOURCE(IDI_NTRDPC));
	wc.lpszClassName = appname;
	if (!RegisterClass(&wc))
		return 1;
	hwnd = CreateWindow(appname, appname, WS_OVERLAPPEDWINDOW,
			    CW_USEDEFAULT, CW_USEDEFAULT, 656, 518,
			    NULL, NULL, hi, NULL);
	if (!hwnd)
		return 1;
	m = GetSystemMenu(hwnd, FALSE);
	AppendMenu(m, MF_SEPARATOR, 0, NULL);
	AppendMenu(m, MF_STRING, IDM_CAD, "Ctrl+Alt+&Del");
	AppendMenu(m, MF_STRING, IDM_FULL, "&Full screen\tCtrl+Alt+Enter");
	AppendMenu(m, MF_STRING, IDM_ABOUT, "&About ntrdpc");

	session_start();
	while (GetMessage(&msg, NULL, 0, 0))
		DispatchMessage(&msg);
	WSACleanup();
	return (int)msg.wParam;
}
