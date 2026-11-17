/*
 * ntrdpc.h - ntrdpc, an RDP client for Windows NT 3.1 to 4.0.
 *
 * The protocol core (rdp.c, mppc.c, bitmap.c, orders.c, draw.c) is plain
 * C89 and knows nothing about Windows.  A front end (window.c and dialog.c
 * on NT, test/headless.c on Unix) owns the socket and the screen and gives
 * the core the ui_* functions at the end of this file.
 */

#ifndef NTRDPC_H
#define NTRDPC_H

#define NTRDPC_VERSION	"0.1"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;		/* 32 bits on every NT CPU and on Unix */
typedef signed char s8;
typedef short s16;

/* a rectangle: right and bottom are exclusive */
typedef struct {
	int l, t, r, b;
} BOX;


/*
 * The frame buffer: the remote desktop at the session depth.  The rows go
 * bottom-up, 4-byte aligned, so the front end can hand it to GDI as a DIB.
 * 8 bpp: palette indices.  15 bpp: RGB555, 16 bpp: RGB565, both as 2 bytes.
 * 24 bpp: 3 bytes B, G, R.  A pixel value is the bytes read little-endian.
 */
typedef struct {
	int w, h;
	int bpp;			/* 8, 15, 16 or 24 */
	int Bpp;			/* bytes per pixel: 1, 2, 2 or 3 */
	int stride;			/* bytes per row */
	u8 *bits;
	u8 pal[256][3];			/* 8 bpp: R, G, B */
} FBUF;

#define FB_ROW(f, y)	((f)->bits + (long)((f)->h - 1 - (y)) * (f)->stride)

/* a brush of PatBlt and the text orders */
typedef struct {
	int style;			/* 0 solid, 1 null, 2 hatched, 3 pattern */
	int orgx, orgy;			/* where pattern pixel 0,0 lands */
	u8 rows[8];			/* top row first, bit 7 = left pixel */
	u32 fore;			/* solid color, and the 0 bits */
	u32 back;			/* the 1 bits */
} RBRUSH;

/* draw.c */
int fb_alloc(FBUF *f, int w, int h, int bpp);
void fb_free(FBUF *f);
u32 fb_color(const FBUF *f, u32 tscolor);
void fb_screen(const FBUF *f, BOX *clip);
int fb_cut(const BOX *clip, int *x, int *y, int *w, int *h, int *sx, int *sy);
void fb_fill(FBUF *f, const BOX *clip, int x, int y, int w, int h, u32 pixel);
void fb_patblt(FBUF *f, const BOX *clip, int x, int y, int w, int h,
	       int rop3, const RBRUSH *br);
void fb_scrblt(FBUF *f, const BOX *clip, int x, int y, int w, int h,
	       int sx, int sy, int rop3);
void fb_memblt(FBUF *f, const BOX *clip, int x, int y, int w, int h,
	       const u8 *src, int srcw, int srch, int sx, int sy, int rop3);
void fb_putbits(FBUF *f, int x, int y, int w, int h, const u8 *src,
		int srcw, int srch);
void fb_line(FBUF *f, const BOX *clip, int x1, int y1, int x2, int y2,
	     int rop2, u32 pixel);
void fb_glyph(FBUF *f, const BOX *clip, int x, int y, int cx, int cy,
	      const u8 *bits, u32 pixel);
void fb_save(FBUF *f, u8 *buf, long bufpels, long pos, int x, int y,
	     int w, int h, int restore);

/* bitmap.c: interleaved RLE; out gets h rows of w pixels, bottom row first */
int rle_decode(const u8 *in, int len, u8 *out, int w, int h, int bpp);

/* mppc.c */
typedef struct MPPC MPPC;
MPPC *mppc_new(void);
void mppc_free(MPPC *m);
int mppc_expand(MPPC *m, const u8 *in, int len, int flags, const u8 **out,
		int *outlen);

/* crypt.c: MD4, MD5, SHA-1, HMAC-MD5 and RC4 */
#define MD_MD5		0
#define MD_MD4		1
#define MD_SHA1		2

typedef struct {
	u32 h[5];
	u32 lo, hi;			/* bytes so far */
	u8 buf[64];
	int kind;			/* MD_* */
} MD;

typedef struct {
	MD in;
	u8 key[16];
} HMAC;

typedef struct {
	u8 s[256];
	int i, j;
} RC4;

void md_init(MD *m, int kind);
void md_update(MD *m, const u8 *p, int n);
void md_final(MD *m, u8 *out);			/* 16 bytes; SHA-1: 20 */
void md_sum(int kind, const u8 *p, int n, u8 *out);
void hmac_init(HMAC *h, const u8 *key);		/* HMAC-MD5, 16-byte key */
void hmac_final(HMAC *h, u8 *out);
void hmac_md5(const u8 *key, const u8 *p, int n, u8 *out);
void rc4_init(RC4 *k, const u8 *key, int len);
void rc4(RC4 *k, const u8 *in, u8 *out, int n);


/*
 * The session.
 */

typedef struct {
	char user[64];
	char password[64];
	char domain[64];
	char client[16];		/* this computer's name */
	int width, height;		/* asked for; ntrdps sends its own */
	int bpp;			/* asked for: 8, 15, 16 or 24 */
	int compress;			/* ask for MPPC compression */
	u32 keylayout;			/* e.g. 0x409 */
	int plain;			/* ask for plain RDP only: no TLS */
	u32 perf;			/* what Windows leaves out: PERF_* */
} RDPOPT;

/* performanceFlags of the Client Info (MS-RDPBCGR 2.2.1.11.1.1.1) */
#define PERF_NO_WALLPAPER	0x01
#define PERF_NO_WINDOWDRAG	0x02	/* full window drag */
#define PERF_NO_ANIMATIONS	0x04	/* menu and window animations */
#define PERF_NO_THEMES		0x08
#define PERF_NO_CURSORSHADOW	0x20
#define PERF_FAST		0x2F	/* all 5, as rdesktop -x m (modem) */

/* states */
#define RS_CONNECT	1		/* sent X.224 CR */
#define RS_TLS		2		/* TLS handshake */
#define RS_NLA		3		/* NLA (CredSSP) logon */
#define RS_MCS		4		/* sent MCS Connect-Initial */
#define RS_ATTACH	5		/* sent Erect Domain + Attach User */
#define RS_JOIN		6		/* joining the channels */
#define RS_LICENSE	7		/* sent Client Info */
#define RS_DEMAND	8		/* waiting for Demand Active */
#define RS_FINAL	9		/* sent Confirm Active */
#define RS_ACTIVE	10		/* got Font Map: running */
#define RS_DONE		11		/* ended */

/* the security the server chose (RDP_NEG_RSP) */
#define PROTO_RDP	0		/* plain RDP */
#define PROTO_SSL	1		/* TLS */
#define PROTO_HYBRID	2		/* TLS and NLA (CredSSP) */

typedef struct ORDSTATE ORDSTATE;
typedef struct TLS TLS;
typedef struct NLA NLA;
typedef struct SEC SEC;

/* security header flags (MS-RDPBCGR 2.2.8.1.1.2.1) */
#define SEC_EXCHANGE_PKT	0x0001
#define SEC_ENCRYPT		0x0008
#define SEC_INFO_PKT		0x0040
#define SEC_LICENSE_PKT		0x0080

typedef struct RDP {
	RDPOPT opt;
	void *ui;			/* the front end's own pointer */
	int state;
	int userid;			/* our MCS user, e.g. 1004 */
	int joined;			/* channels joined so far */
	u32 shareid;
	int bye;			/* we asked to end */
	u32 errinfo;			/* Set Error Info code */
	char err[200];			/* why the session ended */
	int again;			/* the server takes plain RDP only:
					   connect again with opt.plain */
	u32 proto;			/* PROTO_* */
	int negflags;			/* flags of the RDP_NEG_RSP */
	TLS *tls;
	NLA *nla;
	SEC *sec;			/* RC4 security and licensing */

	u8 *in;				/* bytes received, not used yet */
	int inlen, incap;
	u8 *tmp;			/* bitmap decoding */
	long tmpsize;
	u8 *frag;			/* a fast-path update in fragments */
	long fraglen, fragcap;

	FBUF fb;
	MPPC *mppc;
	ORDSTATE *ord;
} RDP;

/* rdp.c */
RDP *rdp_new(const RDPOPT *opt, void *ui);
void rdp_free(RDP *r);
void rdp_start(RDP *r);
int rdp_recv(RDP *r, const u8 *data, int len);
void rdp_closed(RDP *r);
void rdp_key(RDP *r, int flags, int scancode);
void rdp_mouse(RDP *r, int flags, int x, int y);
void rdp_sync(RDP *r, int toggles);
void rdp_refresh(RDP *r, int x, int y, int w, int h);
void rdp_suppress(RDP *r, int allow);
void rdp_close(RDP *r);
const char *rdp_error_text(RDP *r);
void rdp_fail(RDP *r, const char *msg);

/* rdp.c, for tls.c and nla.c */
int rdp_keep(RDP *r, const u8 *data, int len);	/* plain bytes received */
void rdp_out(RDP *r, const u8 *data, int len);	/* bytes to send */
void rdp_tls_up(RDP *r);			/* the handshake is done */
void rdp_nla_done(RDP *r);			/* the NLA logon is done */

/* rdp.c, for sec.c: send RDP data on the I/O channel; d has 32 bytes of
   room in front for the headers */
void rdp_send_sec(RDP *r, u8 *d, int n, int flags);

/* tls.c */
int tls_start(RDP *r);
void tls_free(TLS *t);
int tls_input(RDP *r, const u8 *d, int n);
void tls_send(RDP *r, const u8 *d, int n);
int tls_server_key(RDP *r, const u8 **key, int *len);
void rdp_random(RDP *r, u8 *out, int len);
long der_read(const u8 **p, const u8 *end, int tag);
int cert_key(const u8 *cert, int len, const u8 **key, int *keylen);

/* sec.c: Standard RDP Security (RC4, Windows 2000 to 2003) and licensing */
int sec_server_data(RDP *r, const u8 *p, int n);	/* SC_SECURITY */
int sec_on(RDP *r);				/* RC4 runs */
void sec_exchange(RDP *r);			/* the client random */
void sec_encrypt(RDP *r, u8 *d, int n, u8 *mac);
void sec_decrypt(RDP *r, u8 *d, int n);
void sec_license(RDP *r, const u8 *p, int n);	/* a licensing PDU */
void sec_free(SEC *s);

/* nla.c */
void nla_start(RDP *r);
void nla_free(NLA *a);
void nla_input(RDP *r, u8 *p, int n);

/* keyboard event flags */
#define RK_EXT		0x0100
#define RK_EXT1		0x0200
#define RK_DOWN		0x4000		/* was down before: a repeat */
#define RK_UP		0x8000

/* mouse event flags */
#define RM_WHEEL	0x0200
#define RM_NEGATIVE	0x0100
#define RM_MOVE		0x0800
#define RM_B1		0x1000
#define RM_B2		0x2000
#define RM_B3		0x4000
#define RM_DOWN		0x8000

/* sync toggles */
#define TOG_SCROLL	1
#define TOG_NUM		2
#define TOG_CAPS	4

/* orders.c */
ORDSTATE *orders_new(void);
void orders_free(ORDSTATE *o);
void orders_reset(ORDSTATE *o);
int orders_process(RDP *r, const u8 *p, int len, int count);
int orders_capsets(u8 *out, int Bpp, int *count);


/*
 * The front end gives these to the core.
 */

void ui_send(RDP *r, const u8 *data, int len);
void ui_resize(RDP *r);				/* new size or depth in r->fb */
void ui_palette(RDP *r);			/* r->fb.pal changed */
void ui_invalidate(RDP *r, int x, int y, int w, int h);
void ui_state(RDP *r);				/* r->state changed */
void ui_random(RDP *r, u8 *buf, int len);	/* bytes hard to guess */

/* pointers: 32 x 32, rows top-down; and: 4 bytes a row, 1 = transparent;
   rgb: 3 bytes R, G, B a pixel */
void ui_pointer_new(RDP *r, int index, int hotx, int hoty,
		    const u8 *and, const u8 *rgb);
void ui_pointer_cached(RDP *r, int index);
void ui_pointer_system(RDP *r, int visible);

#endif
