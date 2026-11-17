/*
 * rdp.c - the RDP session: X.224, MCS, GCC, Client Info, licensing, the
 * capability exchange, updates, pointers and input.  The security: none
 * (ntrdps), TLS and NLA (tls.c, nla.c), or Standard RDP Security with RC4
 * (sec.c, Windows 2000 to 2003).  MS-RDPBCGR; the byte layouts follow the
 * ntrdps build sheets.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ntrdpc.h"

#define SERVER_USER	1002
#define IO_CHANNEL	1003
#define HEAD		32		/* room for TPKT, X.224, MCS and the
				   security header */

typedef struct {
	u8 b[8192];
	int n;
} PKT;

static void
p8(PKT *k, int v)
{
	if (k->n < (int)sizeof(k->b))
		k->b[k->n++] = (u8)v;
}

static void
p16(PKT *k, int v)
{
	p8(k, v);
	p8(k, v >> 8);
}

static void
p16be(PKT *k, int v)
{
	p8(k, v >> 8);
	p8(k, v);
}

static void
p32(PKT *k, u32 v)
{
	p16(k, (int)(v & 0xFFFF));
	p16(k, (int)(v >> 16));
}

static void
pzero(PKT *k, int n)
{
	while (n-- > 0)
		p8(k, 0);
}

static void
pbytes(PKT *k, const void *d, int n)
{
	const u8 *s = (const u8 *)d;

	while (n-- > 0)
		p8(k, *s++);
}

/* a string as UTF-16LE (Latin-1 in, so one byte is one character) */
static void
pwide(PKT *k, const char *s)
{
	while (*s)
		p16(k, (u8)*s++);
}

static int
le16(const u8 *p)
{
	return p[0] | p[1] << 8;
}

static u32
le32(const u8 *p)
{
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

/* BER length */
static void
pberlen(PKT *k, int n)
{
	if (n >= 0x100) {
		p8(k, 0x82);
		p16be(k, n);
	} else if (n >= 0x80) {
		p8(k, 0x81);
		p8(k, n);
	} else {
		p8(k, n);
	}
}

/* BER INTEGER */
static void
pberint(PKT *k, u32 v)
{
	u8 b[5];
	int n = 0, i;

	do {
		b[n++] = (u8)v;
		v >>= 8;
	} while (v);
	if (b[n - 1] & 0x80)
		b[n++] = 0;
	p8(k, 0x02);
	p8(k, n);
	for (i = n - 1; i >= 0; i--)
		p8(k, b[i]);
}


/*
 * Sending.
 */

/* to the server: through TLS once it runs */
void
rdp_out(RDP *r, const u8 *d, int n)
{
	if (r->tls)
		tls_send(r, d, n);
	else
		ui_send(r, d, n);
}

/* k->b[HEAD..n) is a whole X.224 TPDU: only the TPKT header goes in front */
static void
send_tpkt(RDP *r, PKT *k)
{
	int n = k->n - HEAD;
	u8 *p = k->b + HEAD - 4;

	p[0] = 3;
	p[1] = 0;
	p[2] = (u8)((n + 4) >> 8);
	p[3] = (u8)(n + 4);
	rdp_out(r, p, n + 4);
}

/* k->b[HEAD..n) is the payload of an X.224 Data TPDU */
static void
send_x224(RDP *r, PKT *k)
{
	int n = k->n - HEAD;
	u8 *p = k->b + HEAD - 7;

	p[0] = 3;
	p[1] = 0;
	p[2] = (u8)((n + 7) >> 8);
	p[3] = (u8)(n + 7);
	p[4] = 2;
	p[5] = 0xF0;
	p[6] = 0x80;
	rdp_out(r, p, n + 7);
}

/* d[0..n) is data for the I/O channel, with 32 bytes of room in front for
   the headers: the security header (flags SEC_*; with RC4 every PDU but
   the licensing ones is encrypted), MCS Send Data Request, X.224, TPKT */
void
rdp_send_sec(RDP *r, u8 *d, int n, int flags)
{
	int h;
	u8 *p;

	if (sec_on(r) && !(flags & SEC_LICENSE_PKT))
		flags |= SEC_ENCRYPT;
	if (flags & SEC_ENCRYPT) {
		d -= 12;
		sec_encrypt(r, d + 12, n, d + 4);
		n += 12;
	} else if (flags) {
		d -= 4;
		n += 4;
	}
	if (flags) {
		d[0] = (u8)flags;
		d[1] = (u8)(flags >> 8);
		d[2] = 0;
		d[3] = 0;
	}
	h = n < 128 ? 7 : 8;
	p = d - h - 7;
	p[0] = 3;
	p[1] = 0;
	p[2] = (u8)((n + h + 7) >> 8);
	p[3] = (u8)(n + h + 7);
	p[4] = 2;
	p[5] = 0xF0;
	p[6] = 0x80;
	p[7] = 0x64;
	p[8] = (u8)((r->userid - 1001) >> 8);
	p[9] = (u8)(r->userid - 1001);
	p[10] = (u8)(IO_CHANNEL >> 8);
	p[11] = (u8)IO_CHANNEL;
	p[12] = 0x70;
	if (n < 128) {
		p[13] = (u8)n;
	} else {
		p[13] = (u8)(0x80 | n >> 8);
		p[14] = (u8)n;
	}
	rdp_out(r, p, n + h + 7);
}

/* k->b[HEAD..n) is data for the I/O channel */
static void
send_sdrq(RDP *r, PKT *k, int flags)
{
	rdp_send_sec(r, k->b + HEAD, k->n - HEAD, flags);
}

static void
start_data(PKT *k)
{
	k->n = HEAD + 18;
}

/* a Share Data PDU; the body is at k->b[HEAD + 18..n) */
static void
send_data(RDP *r, PKT *k, int type2)
{
	int body = k->n - HEAD - 18, n = k->n;

	k->n = HEAD;
	p16(k, 18 + body);		/* totalLength */
	p16(k, 0x17);			/* DATAPDU */
	p16(k, r->userid);
	p32(k, r->shareid);
	p8(k, 0);
	p8(k, 1);			/* streamId */
	p16(k, body + 4);		/* uncompressedLength, as mstsc */
	p8(k, type2);
	p8(k, 0);
	p16(k, 0);
	k->n = n;
	send_sdrq(r, k, 0);
}

static void
send_mcs(RDP *r, const u8 *d, int n)
{
	PKT k;

	k.n = HEAD;
	pbytes(&k, d, n);
	send_x224(r, &k);
}

static void
send_dpum(RDP *r, int reason)
{
	u8 d[2];

	d[0] = (u8)(0x20 | reason >> 1);
	d[1] = (u8)((reason & 1) << 7);
	send_mcs(r, d, 2);
}

static void
send_join(RDP *r, int channel)
{
	u8 d[5];

	d[0] = 0x38;
	d[1] = (u8)((r->userid - 1001) >> 8);
	d[2] = (u8)(r->userid - 1001);
	d[3] = (u8)(channel >> 8);
	d[4] = (u8)channel;
	send_mcs(r, d, 5);
}


/*
 * The session object.
 */

RDP *
rdp_new(const RDPOPT *opt, void *ui)
{
	RDP *r = (RDP *)malloc(sizeof(RDP));

	if (!r)
		return NULL;
	memset(r, 0, sizeof(RDP));
	r->opt = *opt;
	r->ui = ui;
	r->mppc = mppc_new();
	r->ord = orders_new();
	if (!r->mppc || !r->ord) {
		rdp_free(r);
		return NULL;
	}
	return r;
}

void
rdp_free(RDP *r)
{
	if (!r)
		return;
	tls_free(r->tls);
	nla_free(r->nla);
	sec_free(r->sec);
	mppc_free(r->mppc);
	orders_free(r->ord);
	fb_free(&r->fb);
	if (r->in)
		free(r->in);
	if (r->tmp)
		free(r->tmp);
	if (r->frag)
		free(r->frag);
	free(r);
}

void
rdp_fail(RDP *r, const char *msg)
{
	if (r->state == RS_DONE)
		return;
	if (msg != r->err) {
		strncpy(r->err, msg, sizeof(r->err) - 1);
		r->err[sizeof(r->err) - 1] = 0;
	}
	r->state = RS_DONE;
	ui_state(r);
}

static const char *
errinfo_text(u32 code)
{
	switch (code) {
	case 1:
		return "The server ended the session.";
	case 2:
		return "The server logged you off.";
	case 3:
		return "The session was idle for too long.";
	case 4:
		return "The logon took too long.";
	case 5:
		return "Another user connected to the server.";
	case 6:
		return "The server ran out of memory.";
	case 7:
		return "The server refused the connection.";
	case 9:
		return "You are not allowed to log on to this server.";
	case 0xB:
		return "The session was disconnected by the user.";
	case 0xC:
		return "The user logged off.";
	}
	return NULL;
}

/* the reason the session ended; "" when the user ended it */
const char *
rdp_error_text(RDP *r)
{
	static char buf[64];
	const char *t;

	if (r->err[0] || r->bye)
		return r->err;
	if (r->errinfo) {
		t = errinfo_text(r->errinfo);
		if (t)
			return t;
		sprintf(buf, "The server ended the session (code %lu).",
			(unsigned long)r->errinfo);
		return buf;
	}
	return "The server closed the connection.";
}


/*
 * Connection sequence.
 */

void
rdp_start(RDP *r)
{
	PKT k;
	const char *u;
	int li;

	k.n = HEAD;
	p8(&k, 0);			/* LI, below */
	p8(&k, 0xE0);			/* Connection Request */
	p16(&k, 0);
	p16(&k, 0);
	p8(&k, 0);
	if (r->opt.user[0]) {
		pbytes(&k, "Cookie: mstshash=", 17);
		for (u = r->opt.user; *u && u - r->opt.user < 9; u++)
			p8(&k, (*u == '\r' || *u == '\n') ? '_' : *u);
		pbytes(&k, "\r\n", 2);
	}
	/* requestedProtocols: TLS, and NLA when there is a password (NLA
	   logs on before the session, so it needs one) */
	p8(&k, 0x01);			/* RDP_NEG_REQ */
	p8(&k, 0);
	p16(&k, 8);
	p32(&k, r->opt.plain ? 0 : r->opt.password[0] ?
	    PROTO_SSL | PROTO_HYBRID : PROTO_SSL);
	li = k.n - HEAD - 1;
	k.b[HEAD] = (u8)li;
	send_tpkt(r, &k);
	r->state = RS_CONNECT;
	ui_state(r);
}

static void
connect_initial(RDP *r)
{
	PKT blocks, tail, k;
	int n, i;
	char name[16];
	static const u32 params[3][8] = {
		{ 34, 2, 0, 1, 0, 1, 65535, 2 },
		{ 1, 1, 1, 1, 0, 1, 1056, 2 },
		{ 65535, 64535, 65535, 1, 0, 1, 65535, 2 }
	};

	/* CS_CORE */
	blocks.n = 0;
	p16(&blocks, 0xC001);
	p16(&blocks, 216);
	p32(&blocks, 0x00080004);	/* RDP 5 */
	p16(&blocks, r->opt.width);
	p16(&blocks, r->opt.height);
	p16(&blocks, 0xCA01);		/* 8 bpp */
	p16(&blocks, 0xAA03);		/* SASSequence */
	p32(&blocks, r->opt.keylayout);
	p32(&blocks, 2600);		/* clientBuild */
	memset(name, 0, sizeof(name));
	strncpy(name, r->opt.client, 15);
	for (i = 0; i < 16; i++)
		p16(&blocks, (u8)name[i]);
	p32(&blocks, 4);		/* keyboardType: IBM enhanced */
	p32(&blocks, 0);
	p32(&blocks, 12);		/* function keys */
	pzero(&blocks, 64);		/* imeFileName */
	p16(&blocks, 0xCA01);		/* postBeta2ColorDepth */
	p16(&blocks, 1);		/* clientProductId */
	p32(&blocks, 0);		/* serialNumber */
	p16(&blocks, r->opt.bpp);	/* highColorDepth */
	/* supportedColorDepths: every depth up to the one asked for (24 = 1,
	   16 = 2, 15 = 4). ntrdps sends its screen's depth if it is in here,
	   else 8 bpp. Windows 8 and later have no 8 or 15 bpp and end the
	   connection unless 16 is in here: so all depths for a server that
	   sets flags in its RDP_NEG_RSP (Windows; ntrdps sets none). */
	p16(&blocks, r->negflags || r->opt.bpp >= 24 ? 7 :
	    r->opt.bpp >= 16 ? 6 : r->opt.bpp >= 15 ? 4 : 0);
	p16(&blocks, 0x0001);		/* earlyCapabilityFlags: ERRINFO */
	pzero(&blocks, 64);		/* clientDigProductId */
	p8(&blocks, 0);			/* connectionType */
	p8(&blocks, 0);
	p32(&blocks, r->proto);		/* serverSelectedProtocol */
	/* CS_SECURITY: RC4 with 40, 128 and 56-bit keys (sec.c); none
	   under TLS */
	p16(&blocks, 0xC002);
	p16(&blocks, 12);
	p32(&blocks, r->proto == PROTO_RDP ? 0x0B : 0);
	p32(&blocks, 0);
	/* CS_NET: no virtual channels */
	p16(&blocks, 0xC003);
	p16(&blocks, 8);
	p32(&blocks, 0);

	/* GCC Conference Create Request */
	tail.n = 0;
	pbytes(&tail, "\x00\x08\x00\x10\x00\x01\xC0\x00" "Duca", 12);
	p16be(&tail, 0x8000 | blocks.n);
	pbytes(&tail, blocks.b, blocks.n);

	/* MCS Connect-Initial */
	k.n = 0;
	pbytes(&k, "\x04\x01\x01\x04\x01\x01\x01\x01\xFF", 9);
	for (i = 0; i < 3; i++) {
		PKT q;

		q.n = 0;
		for (n = 0; n < 8; n++)
			pberint(&q, params[i][n]);
		p8(&k, 0x30);
		pberlen(&k, q.n);
		pbytes(&k, q.b, q.n);
	}
	p8(&k, 0x04);
	pberlen(&k, 7 + 2 + tail.n);
	pbytes(&k, "\x00\x05\x00\x14\x7C\x00\x01", 7);
	p16be(&k, 0x8000 | tail.n);
	pbytes(&k, tail.b, tail.n);

	blocks.n = HEAD;
	p8(&blocks, 0x7F);
	p8(&blocks, 0x65);
	pberlen(&blocks, k.n);
	pbytes(&blocks, k.b, k.n);
	send_x224(r, &blocks);
	r->state = RS_MCS;
	ui_state(r);
}

static void
x224_cc(RDP *r, const u8 *p, int n)
{
	u32 v = n >= 15 ? le32(p + 11) : 0;

	if (r->state != RS_CONNECT) {
		rdp_fail(r, "The server sent an unexpected answer.");
		return;
	}
	if (n >= 15 && p[7] == 0x03) {		/* RDP_NEG_FAILURE */
		switch (v) {
		case 1:			/* SSL_REQUIRED_BY_SERVER */
		case 5:			/* HYBRID_REQUIRED_BY_SERVER */
			if (r->opt.plain)	/* TLS failed before */
				rdp_fail(r, "The server allows only TLS, and "
					 "its TLS is too old for ntrdpc. "
					 "ntrdpc needs TLS 1.2.");
			else if (v == 1)
				rdp_fail(r, "The server allows only TLS "
					 "connections.");
			else
				rdp_fail(r, "This server wants the user name "
					 "and password first. Type them, then "
					 "connect.");
			break;
		case 2:			/* SSL_NOT_ALLOWED_BY_SERVER */
		case 3:			/* SSL_CERT_NOT_ON_SERVER */
			r->again = 1;
			rdp_fail(r, "The server allows no TLS.");
			break;
		default:
			rdp_fail(r, "The server refused the connection "
				 "(negotiation failure).");
			break;
		}
		return;
	}
	/* RDP_NEG_RSP; none from servers older than Windows 2003 SP1 */
	r->proto = n >= 15 && p[7] == 0x02 ? v : PROTO_RDP;
	r->negflags = n >= 15 && p[7] == 0x02 ? p[8] : 0;
	if (r->proto == PROTO_RDP) {
		connect_initial(r);
		return;
	}
	if (r->proto != PROTO_SSL && r->proto != PROTO_HYBRID) {
		rdp_fail(r, "The server chose a security ntrdpc does not know.");
		return;
	}
	r->state = RS_TLS;
	ui_state(r);
	tls_start(r);
}

/* TLS runs: NLA first if the server chose it, then MCS */
void
rdp_tls_up(RDP *r)
{
	if (r->proto == PROTO_HYBRID)
		nla_start(r);
	else
		connect_initial(r);
}

void
rdp_nla_done(RDP *r)
{
	connect_initial(r);
}

/* BER: read a tag and a length; returns the length or -1 */
static int
ber(const u8 **p, const u8 *end, int tag)
{
	int n, k;

	if (end - *p < 2 || **p != tag)
		return -1;
	(*p)++;
	n = *(*p)++;
	if (n & 0x80) {
		k = n & 0x7F;
		if (k > 2 || end - *p < k)
			return -1;
		n = 0;
		while (k-- > 0)
			n = n << 8 | *(*p)++;
	}
	return end - *p < n ? -1 : n;
}

static void
connect_response(RDP *r, const u8 *p, int n)
{
	const u8 *end = p + n, *q;
	int len, type, blen;

	if (n < 2 || p[0] != 0x7F || p[1] != 0x66) {
		rdp_fail(r, "The server sent no MCS Connect-Response.");
		return;
	}
	p += 2;
	len = *p++;
	if (len & 0x80)
		p += len & 0x7F;
	len = ber(&p, end, 0x0A);	/* result */
	if (len < 1 || p[len - 1] != 0) {
		rdp_fail(r, "The server refused the MCS connection.");
		return;
	}
	/* find the server data blocks after "McDn" */
	for (q = p; q + 4 <= end; q++)
		if (q[0] == 'M' && q[1] == 'c' && q[2] == 'D' && q[3] == 'n')
			break;
	if (q + 4 > end) {
		rdp_fail(r, "The server sent no GCC data.");
		return;
	}
	q += 4;
	if (q < end && (*q & 0x80))
		q += 2;
	else
		q++;
	while (end - q >= 4) {
		type = le16(q);
		blen = le16(q + 2);
		if (blen < 4 || blen > end - q)
			break;
		if (type == 0x0C02 && r->proto == PROTO_RDP &&	/* SC_SECURITY */
		    !sec_server_data(r, q, blen))
			return;
		q += blen;
	}
	send_mcs(r, (const u8 *)"\x04\x01\x00\x01\x00", 5);	/* EDrq */
	send_mcs(r, (const u8 *)"\x28", 1);			/* AUrq */
	r->state = RS_ATTACH;
	ui_state(r);
}

static void
client_info(RDP *r)
{
	PKT k;
	u32 flags = 0x4173;	/* MOUSE, DISABLECTRLALTDEL, UNICODE, MAXIMIZESHELL,
				   LOGONNOTIFY, ENABLEWINDOWSKEY, FORCE_ENCRYPTED */
	int dl = (int)strlen(r->opt.domain), ul = (int)strlen(r->opt.user);
	int pl = (int)strlen(r->opt.password);
	const char *addr = "0.0.0.0", *dir = "ntrdpc";

	if (r->opt.compress)
		flags |= 0x0080 | (1 << 9);	/* MPPC, 64K */
	if (pl)
		flags |= 0x0008;		/* AUTOLOGON */
	k.n = HEAD;
	p32(&k, r->opt.keylayout);	/* CodePage */
	p32(&k, flags);
	p16(&k, dl * 2);
	p16(&k, ul * 2);
	p16(&k, pl * 2);
	p16(&k, 0);
	p16(&k, 0);
	pwide(&k, r->opt.domain);
	p16(&k, 0);
	pwide(&k, r->opt.user);
	p16(&k, 0);
	pwide(&k, r->opt.password);
	p16(&k, 0);
	p16(&k, 0);			/* AlternateShell */
	p16(&k, 0);			/* WorkingDir */
	p16(&k, 2);			/* AF_INET */
	p16(&k, (int)strlen(addr) * 2 + 2);
	pwide(&k, addr);
	p16(&k, 0);
	p16(&k, (int)strlen(dir) * 2 + 2);
	pwide(&k, dir);
	p16(&k, 0);
	pzero(&k, 172);			/* time zone */
	p32(&k, 0);			/* clientSessionId */
	p32(&k, r->opt.perf);		/* performanceFlags */
	p16(&k, 0);			/* cbAutoReconnectCookie */
	send_sdrq(r, &k, SEC_INFO_PKT);
	memset(k.b, 0, sizeof(k.b));	/* the password */
	r->state = RS_LICENSE;
	ui_state(r);
}

/* a licensing PDU without RC4 (plain RDP, TLS): the basic security
   header with SEC_LICENSE_PKT, and wMsgSize fits; else a share PDU */
static int
is_license(const u8 *p, int n)
{
	return n >= 8 && (le16(p) & SEC_LICENSE_PKT) && le16(p + 6) == n - 4;
}


/*
 * Activation.
 */

static void
confirm_active(RDP *r)
{
	PKT k;
	int count = 0, start, caps;

	k.n = HEAD + 6;
	p32(&k, r->shareid);
	p16(&k, SERVER_USER);		/* originatorId */
	p16(&k, 6);			/* lengthSourceDescriptor */
	p16(&k, 0);			/* lengthCombinedCapabilities, below */
	pbytes(&k, "MSTSC", 6);
	p16(&k, 0);			/* numberCapabilities, below */
	p16(&k, 0);
	caps = k.n - 4;

	p16(&k, 1);			/* General */
	p16(&k, 24);
	p16(&k, 1);			/* Windows */
	p16(&k, 3);			/* Windows NT */
	p16(&k, 0x0200);
	p16(&k, 0);
	p16(&k, 0);
	p16(&k, 0x0401);		/* NO_BITMAP_COMPRESSION_HDR,
					   FASTPATH_OUTPUT_SUPPORTED */
	p16(&k, 0);
	p16(&k, 0);
	p16(&k, 0);
	p8(&k, 1);			/* refreshRectSupport */
	p8(&k, 1);			/* suppressOutputSupport */
	count++;

	p16(&k, 2);			/* Bitmap */
	p16(&k, 28);
	p16(&k, r->fb.bpp);
	p16(&k, 1);
	p16(&k, 1);
	p16(&k, 1);
	p16(&k, r->fb.w);
	p16(&k, r->fb.h);
	p16(&k, 0);
	p16(&k, 1);			/* desktopResizeFlag */
	p16(&k, 1);			/* bitmapCompressionFlag */
	p8(&k, 0);
	p8(&k, 0);
	p16(&k, 1);			/* multipleRectangleSupport */
	p16(&k, 0);
	count++;

	start = k.n;
	k.n += orders_capsets(k.b + k.n, r->fb.Bpp, &count);
	(void)start;

	p16(&k, 7);			/* Window Activation */
	p16(&k, 12);
	pzero(&k, 8);
	count++;

	p16(&k, 5);			/* Control */
	p16(&k, 12);
	p16(&k, 0);
	p16(&k, 0);
	p16(&k, 2);
	p16(&k, 2);
	count++;

	p16(&k, 8);			/* Pointer */
	p16(&k, 10);
	p16(&k, 1);			/* color pointers */
	p16(&k, 20);
	p16(&k, 21);
	count++;

	p16(&k, 9);			/* Share */
	p16(&k, 8);
	p16(&k, 0);
	p16(&k, 0);
	count++;

	p16(&k, 13);			/* Input */
	p16(&k, 88);
	p16(&k, 0x0001);		/* scancodes */
	p16(&k, 0);
	p32(&k, r->opt.keylayout);
	p32(&k, 4);
	p32(&k, 0);
	p32(&k, 12);
	pzero(&k, 64);
	count++;

	p16(&k, 12);			/* Sound */
	p16(&k, 8);
	p16(&k, 0);
	p16(&k, 0);
	count++;

	p16(&k, 14);			/* Font */
	p16(&k, 8);
	p16(&k, 1);
	p16(&k, 0);
	count++;

	/* fill in the lengths */
	k.b[HEAD + 6 + 8] = (u8)((k.n - caps) & 0xFF);
	k.b[HEAD + 6 + 9] = (u8)((k.n - caps) >> 8);
	k.b[caps] = (u8)count;
	k.b[caps + 1] = (u8)(count >> 8);
	start = k.n;
	k.n = HEAD;
	p16(&k, start - HEAD);		/* totalLength */
	p16(&k, 0x13);			/* CONFIRMACTIVEPDU */
	p16(&k, r->userid);
	k.n = start;
	send_sdrq(r, &k, 0);
}

static void
finalize(RDP *r)
{
	PKT k;

	start_data(&k);			/* Synchronize */
	p16(&k, 1);
	p16(&k, SERVER_USER);
	send_data(r, &k, 31);

	start_data(&k);			/* Control: cooperate */
	p16(&k, 4);
	p16(&k, 0);
	p32(&k, 0);
	send_data(r, &k, 20);

	start_data(&k);			/* Control: request control */
	p16(&k, 1);
	p16(&k, 0);
	p32(&k, 0);
	send_data(r, &k, 20);

	start_data(&k);			/* Font List */
	p16(&k, 0);
	p16(&k, 0);
	p16(&k, 3);
	p16(&k, 0x32);
	send_data(r, &k, 39);
}

static void
demand_active(RDP *r, const u8 *p, int n)
{
	const u8 *end = p + n, *s;
	int srclen, ncaps, type, len, w = r->fb.w, h = r->fb.h;
	int bpp = r->fb.bpp ? r->fb.bpp : r->opt.bpp;

	if (n < 12)
		return;
	r->shareid = le32(p);
	srclen = le16(p + 4);
	s = p + 8 + srclen;
	if (end - s < 4)
		return;
	ncaps = le16(s);
	s += 4;
	while (ncaps-- > 0 && end - s >= 4) {
		type = le16(s);
		len = le16(s + 2);
		if (len < 4 || len > end - s)
			break;
		if (type == 2 && len >= 16) {	/* Bitmap */
			bpp = le16(s + 4);
			w = le16(s + 12);
			h = le16(s + 14);
		}
		s += len;
	}
	if (bpp != 8 && bpp != 15 && bpp != 16 && bpp != 24) {
		rdp_fail(r, "The server uses a color depth ntrdpc cannot show.");
		return;
	}
	if (!r->fb.bits || w != r->fb.w || h != r->fb.h || bpp != r->fb.bpp) {
		if (!fb_alloc(&r->fb, w, h, bpp)) {
			rdp_fail(r, "Out of memory for the remote desktop.");
			return;
		}
		ui_resize(r);
	}
	orders_reset(r->ord);
	confirm_active(r);
	finalize(r);
	r->state = RS_FINAL;
	ui_state(r);
}


/*
 * Updates.
 */

static u8 *
tmpbuf(RDP *r, long size)
{
	if (size > r->tmpsize) {
		if (r->tmp)
			free(r->tmp);
		r->tmp = (u8 *)malloc((size_t)size);
		r->tmpsize = r->tmp ? size : 0;
	}
	return r->tmp;
}

static void
bitmap_update(RDP *r, const u8 *p, int n)
{
	const u8 *end = p + n, *q = p + 4, *data;
	int count, l, t, rr, b, w, h, bpp, flags, len, j, srcrow, rowbytes;
	u8 *buf;

	if (n < 4)
		return;
	count = le16(p + 2);
	while (count-- > 0 && end - q >= 18) {
		l = le16(q);
		t = le16(q + 2);
		rr = le16(q + 4);
		b = le16(q + 6);
		w = le16(q + 8);
		h = le16(q + 10);
		bpp = le16(q + 12);
		flags = le16(q + 14);
		len = le16(q + 16);
		data = q + 18;
		if (len > end - data)
			return;
		q = data + len;
		if (bpp != r->fb.bpp || w == 0 || h == 0)
			continue;
		rowbytes = w * r->fb.Bpp;
		buf = tmpbuf(r, (long)rowbytes * h);
		if (!buf)
			return;
		if (flags & 0x0001) {
			if (!(flags & 0x0400)) {	/* TS_CD_HEADER */
				if (len < 8)
					continue;
				j = le16(data + 2);	/* cbCompMainBodySize */
				data += 8;
				len -= 8;
				if (j < len)
					len = j;
			}
			if (!rle_decode(data, len, buf, w, h, bpp))
				continue;
		} else {
			srcrow = len / h;
			if (srcrow < rowbytes)
				continue;
			for (j = 0; j < h; j++)
				memcpy(buf + (long)j * rowbytes,
				       data + (long)j * srcrow, (size_t)rowbytes);
		}
		fb_putbits(&r->fb, l, t, rr - l + 1, b - t + 1, buf, w, h);
		ui_invalidate(r, l, t, rr - l + 1, b - t + 1);
	}
}

static void
palette_update(RDP *r, const u8 *p, int n)
{
	u32 count;
	int i;

	if (n < 8)
		return;
	count = le32(p + 4);
	if (count > 256 || (long)count * 3 > n - 8)
		return;
	for (i = 0; i < (int)count; i++) {
		r->fb.pal[i][0] = p[8 + i * 3];
		r->fb.pal[i][1] = p[8 + i * 3 + 1];
		r->fb.pal[i][2] = p[8 + i * 3 + 2];
	}
	ui_palette(r);
}

static void
update(RDP *r, const u8 *p, int n)
{
	if (n < 2)
		return;
	if (le16(p) == 2) {
		palette_update(r, p, n);
		return;
	}
	if (!r->fb.bits)
		return;
	switch (le16(p)) {
	case 0:				/* orders */
		if (n >= 8)
			orders_process(r, p + 8, n - 8, le16(p + 4));
		break;
	case 1:
		bitmap_update(r, p, n);
		break;
	}
}

/* a pointer shape, made 32 x 32 with top-down rows */
static void
pointer_shape(RDP *r, const u8 *p, int n, int bpp)
{
	u8 and[128], rgb[32 * 32 * 3];
	const u8 *xm, *am, *s;
	int index, hx, hy, w, h, alen, xlen, xs, as, x, y, sy, a;
	u32 v;
	u8 *d;

	if (n < 14)
		return;
	index = le16(p);
	hx = le16(p + 2);
	hy = le16(p + 4);
	w = le16(p + 6);
	h = le16(p + 8);
	alen = le16(p + 10);
	xlen = le16(p + 12);
	xm = p + 14;
	am = xm + xlen;
	if (14 + xlen + alen > n)
		return;
	xs = ((w * bpp + 15) / 16) * 2;
	as = ((w + 15) / 16) * 2;
	if (xlen < xs * h)
		return;
	if (alen < as * h)
		alen = 0;		/* no usable AND mask: opaque */
	memset(and, 0xFF, sizeof(and));
	memset(rgb, 0, sizeof(rgb));
	for (y = 0; y < h && y < 32; y++) {
		sy = bpp == 1 ? y : h - 1 - y;
		for (x = 0; x < w && x < 32; x++) {
			a = alen ? (am[sy * as + x / 8] >> (7 - x % 8)) & 1 : 0;
			if (!a)
				and[y * 4 + x / 8] &= (u8)~(0x80 >> (x % 8));
			d = rgb + (y * 32 + x) * 3;
			s = xm + sy * xs;
			switch (bpp) {
			case 1:
				if ((s[x / 8] >> (7 - x % 8)) & 1)
					d[0] = d[1] = d[2] = 0xFF;
				break;
			case 8:
				memcpy(d, r->fb.pal[s[x]], 3);
				break;
			case 15:
			case 16:
				v = le16(s + x * 2);
				if (bpp == 15) {
					d[0] = (u8)((v >> 10 & 31) << 3);
					d[1] = (u8)((v >> 5 & 31) << 3);
				} else {
					d[0] = (u8)((v >> 11 & 31) << 3);
					d[1] = (u8)((v >> 5 & 63) << 2);
				}
				d[2] = (u8)((v & 31) << 3);
				break;
			case 24:
			case 32:
				s += x * (bpp / 8);
				d[0] = s[2];
				d[1] = s[1];
				d[2] = s[0];
				break;
			}
		}
	}
	ui_pointer_new(r, index, hx < 32 ? hx : 31, hy < 32 ? hy : 31, and,
		       rgb);
}

static void
pointer_pdu(RDP *r, const u8 *p, int n)
{
	if (n < 4)
		return;
	switch (le16(p)) {
	case 1:				/* SYSTEM */
		if (n >= 8)
			ui_pointer_system(r, le32(p + 4) != 0);
		break;
	case 6:				/* COLOR */
		pointer_shape(r, p + 4, n - 4, 24);
		break;
	case 7:				/* CACHED */
		if (n >= 6)
			ui_pointer_cached(r, le16(p + 4));
		break;
	case 8:				/* POINTER with xorBpp */
		if (n >= 6)
			pointer_shape(r, p + 6, n - 6, le16(p + 4));
		break;
	}
}

/* one fast-path update, whole (MS-RDPBCGR 2.2.9.1.2.1) */
static void
fp_update(RDP *r, int code, const u8 *p, int n)
{
	switch (code) {
	case 0x0:			/* orders: numberOrders, then orders */
		if (n >= 2 && r->fb.bits)
			orders_process(r, p + 2, n - 2, le16(p));
		break;
	case 0x1:			/* bitmap, from updateType on */
		if (r->fb.bits)
			bitmap_update(r, p, n);
		break;
	case 0x2:			/* palette, from updateType on */
		palette_update(r, p, n);
		break;
	case 0x5:			/* pointer hidden */
		ui_pointer_system(r, 0);
		break;
	case 0x6:			/* default pointer */
		ui_pointer_system(r, 1);
		break;
	case 0x9:			/* color pointer */
		pointer_shape(r, p, n, 24);
		break;
	case 0xA:			/* cached pointer */
		if (n >= 2)
			ui_pointer_cached(r, le16(p));
		break;
	case 0xB:			/* pointer with xorBpp */
		if (n >= 2)
			pointer_shape(r, p + 2, n - 2, le16(p));
		break;
	}
}

/* a fast-path output PDU: one or more updates, maybe compressed, maybe
   in fragments (Windows 8 and later send their screen only this way) */
static void
fastpath(RDP *r, u8 *p, int n)
{
	const u8 *end = p + n, *data;
	int code, frag, flags, len, hl = p[1] & 0x80 ? 3 : 2;
	u8 *q;

	if (p[0] & 0x80) {	/* FASTPATH_OUTPUT_ENCRYPTED: a MAC, then data */
		if (!sec_on(r) || n < hl + 8) {
			rdp_fail(r, "The server sent encrypted fast-path data.");
			return;
		}
		sec_decrypt(r, p + hl + 8, n - hl - 8);
		hl += 8;
	}
	p += hl;
	while (end - p >= 3 && r->state != RS_DONE) {
		code = p[0] & 0x0F;
		frag = p[0] >> 4 & 3;
		flags = 0;
		if (p[0] & 0x80)	/* FASTPATH_OUTPUT_COMPRESSION_USED */
			flags = *++p;
		p++;
		if (end - p < 2)
			break;
		len = le16(p);
		p += 2;
		if (len > end - p) {
			rdp_fail(r, "The server sent a bad fast-path update.");
			return;
		}
		data = p;
		p += len;
		if ((flags & 0xE0) &&
		    !mppc_expand(r->mppc, data, len, flags, &data, &len)) {
			rdp_fail(r, "The server sent bad compressed data.");
			return;
		}
		if (frag) {		/* 2 first, 3 next, 1 last */
			if (frag == 2)
				r->fraglen = 0;
			if (r->fraglen + len > r->fragcap) {
				q = (u8 *)realloc(r->frag,
						  (size_t)(r->fraglen + len + 16384));
				if (!q) {
					rdp_fail(r, "Out of memory.");
					return;
				}
				r->frag = q;
				r->fragcap = r->fraglen + len + 16384;
			}
			memcpy(r->frag + r->fraglen, data, (size_t)len);
			r->fraglen += len;
			if (frag != 1)
				continue;
			data = r->frag;
			len = (int)r->fraglen;
		}
		fp_update(r, code, data, len);
	}
}

static void
data_pdu(RDP *r, const u8 *p, int n)
{
	const u8 *body;
	int len, type2, ctype;

	if (n < 12)
		return;
	type2 = p[8];
	ctype = p[9];
	body = p + 12;
	len = n - 12;
	if ((ctype & 0xE0) &&
	    !mppc_expand(r->mppc, body, len, ctype, &body, &len)) {
		rdp_fail(r, "The server sent bad compressed data.");
		return;
	}
	switch (type2) {
	case 2:				/* Update */
		update(r, body, len);
		break;
	case 27:			/* Pointer */
		pointer_pdu(r, body, len);
		break;
	case 40:			/* Font Map: the end of the activation */
		if (r->state == RS_FINAL) {
			r->state = RS_ACTIVE;
			ui_state(r);
		}
		break;
	case 47:			/* Set Error Info */
		if (len >= 4)
			r->errinfo = le32(body);
		break;
	}
}

static void
share(RDP *r, const u8 *p, int n)
{
	int total;

	while (n >= 4 && r->state != RS_DONE) {
		total = le16(p);
		if (total == 0x8000) {		/* flow PDU */
			if (n < 8)
				break;
			p += 8;
			n -= 8;
			continue;
		}
		if (total < 6 || total > n)
			break;
		switch (le16(p + 2) & 0x0F) {
		case 1:				/* Demand Active */
			demand_active(r, p + 6, total - 6);
			break;
		case 6:				/* Deactivate All */
			r->state = RS_DEMAND;
			ui_state(r);
			break;
		case 7:				/* Data */
			if (r->state >= RS_FINAL || r->state == RS_DEMAND)
				data_pdu(r, p + 6, total - 6);
			break;
		}
		p += total;
		n -= total;
	}
}

/* the result of an Attach User or Channel Join Confirm (PER) */
static int
mcs_result(const u8 *p)
{
	return (p[0] & 1) << 3 | p[1] >> 5;
}

static void
mcs(RDP *r, u8 *p, int n)
{
	int len, flags, hl;

	if (r->state == RS_MCS) {
		connect_response(r, p, n);
		return;
	}
	if (n < 1)
		return;
	switch (p[0] >> 2) {
	case 8:					/* Disconnect Provider Ultimatum */
		rdp_fail(r, rdp_error_text(r));
		break;
	case 11:				/* Attach User Confirm */
		if (r->state != RS_ATTACH || n < 4 || mcs_result(p) != 0) {
			rdp_fail(r, "The server refused the MCS user.");
			break;
		}
		r->userid = 1001 + (p[2] << 8 | p[3]);
		send_join(r, r->userid);
		r->joined = 0;
		r->state = RS_JOIN;
		ui_state(r);
		break;
	case 15:				/* Channel Join Confirm */
		if (r->state != RS_JOIN || n < 2 || mcs_result(p) != 0) {
			rdp_fail(r, "The server refused an MCS channel.");
			break;
		}
		if (r->joined++ == 0) {
			send_join(r, IO_CHANNEL);
		} else {
			sec_exchange(r);	/* with RC4 only */
			if (r->state != RS_DONE)
				client_info(r);
		}
		break;
	case 26:				/* Send Data Indication */
		if (n < 7)
			break;
		len = p[6];
		p += 7;
		n -= 7;
		if (len & 0x80) {
			if (n < 1)
				break;
			len = (len & 0x3F) << 8 | *p++;
			n--;
		}
		if (len > n)
			len = n;
		if (sec_on(r)) {	/* every PDU has a security header */
			if (len < 4)
				break;
			flags = le16(p);
			hl = flags & SEC_ENCRYPT ? 12 : 4;
			if (len < hl)
				break;
			if (flags & SEC_ENCRYPT)
				sec_decrypt(r, p + 12, len - 12);
			p += hl;
			len -= hl;
			if (flags & SEC_LICENSE_PKT) {
				sec_license(r, p, len);
				break;
			}
		} else if (r->state == RS_LICENSE && is_license(p, len)) {
			sec_license(r, p + 4, len - 4);
			break;
		}
		share(r, p, len);
		break;
	}
}

static void
tpkt(RDP *r, u8 *p, int n)
{
	if (n < 2)
		return;
	switch (p[1] & 0xF0) {
	case 0xD0:				/* Connection Confirm */
		x224_cc(r, p, n);
		break;
	case 0x80:				/* Disconnect Request */
		rdp_fail(r, r->state == RS_CONNECT ?
			 "The server refused the connection." :
			 rdp_error_text(r));
		break;
	case 0xF0:				/* Data */
		if (p[0] + 1 <= n)
			mcs(r, p + p[0] + 1, n - p[0] - 1);
		break;
	}
}

/* plain bytes from the server, kept until a whole PDU is there */
int
rdp_keep(RDP *r, const u8 *data, int len)
{
	u8 *p;

	if (r->inlen + len > r->incap) {
		p = (u8 *)realloc(r->in, (size_t)(r->inlen + len + 4096));
		if (!p) {
			rdp_fail(r, "Out of memory.");
			return 0;
		}
		r->in = p;
		r->incap = r->inlen + len + 4096;
	}
	memcpy(r->in + r->inlen, data, (size_t)len);
	r->inlen += len;
	return 1;
}

/* the size of the CredSSP message (a DER SEQUENCE) at p: 0 while it is
   not all there, -1 if it is bad */
static int
derlen(const u8 *p, int avail)
{
	int k, i, n = 0;

	if (avail < 2)
		return 0;
	if (p[0] != 0x30)
		return -1;
	if (!(p[1] & 0x80))
		return 2 + p[1];
	k = p[1] & 0x7F;
	if (k < 1 || k > 3)
		return -1;
	if (avail < 2 + k)
		return 0;
	for (i = 0; i < k; i++)
		n = n << 8 | p[2 + i];
	return n > 0x100000L ? -1 : 2 + k + n;
}

/* the whole PDUs in r->in */
static void
parse(RDP *r)
{
	int off = 0, plen, avail, was_tls = r->tls != NULL;
	u8 *p;

	while (r->state != RS_DONE) {
		avail = r->inlen - off;
		p = r->in + off;
		if (r->state == RS_NLA) {	/* CredSSP messages */
			plen = derlen(p, avail);
			if (plen < 0) {
				rdp_fail(r, "The server sent a bad NLA message.");
				break;
			}
			if (plen == 0 || avail < plen)
				break;
			nla_input(r, p, plen);
			off += plen;
			continue;
		}
		if (avail < 4)
			break;
		if (p[0] == 3) {
			plen = p[2] << 8 | p[3];
			if (plen < 7) {
				rdp_fail(r, "The server sent a bad packet.");
				break;
			}
		} else {			/* fast-path */
			plen = p[1];
			if (plen & 0x80)
				plen = (plen & 0x7F) << 8 | p[2];
			if (plen < 3) {
				rdp_fail(r, "The server sent a bad packet.");
				break;
			}
		}
		if (avail < plen)
			break;
		if (p[0] == 3)
			tpkt(r, p + 4, plen - 4);
		else if (r->state >= RS_DEMAND && r->state != RS_DONE)
			fastpath(r, p, plen);
		off += plen;
		if (!was_tls && r->tls)		/* TLS started: the rest is */
			break;			/* TLS records */
	}
	if (off) {
		memmove(r->in, r->in + off, (size_t)(r->inlen - off));
		r->inlen -= off;
	}
}

/* bytes from the server; 0 when the session is over */
int
rdp_recv(RDP *r, const u8 *data, int len)
{
	int was_tls = r->tls != NULL, n;
	u8 *t;

	if (was_tls ? !tls_input(r, data, len) : !rdp_keep(r, data, len))
		return 0;
	parse(r);
	if (!was_tls && r->tls && r->inlen > 0 && r->state != RS_DONE) {
		/* bytes after the X.224 answer: already TLS */
		n = r->inlen;
		t = (u8 *)malloc((size_t)n);
		if (!t) {
			rdp_fail(r, "Out of memory.");
			return 0;
		}
		memcpy(t, r->in, (size_t)n);
		r->inlen = 0;
		if (tls_input(r, t, n))
			parse(r);
		free(t);
	}
	return r->state != RS_DONE;
}

/* the socket closed */
void
rdp_closed(RDP *r)
{
	if (r->state == RS_TLS) {
		r->again = 1;		/* maybe an older TLS: try plain RDP */
		rdp_fail(r, "The server ended the TLS handshake.");
	}
	else if (r->state == RS_NLA)
		rdp_fail(r, "The server ended the NLA logon. Wrong user name "
			 "or password?");
	else
		rdp_fail(r, rdp_error_text(r));
}


/*
 * Input and requests.
 */

static int
active(RDP *r)
{
	return r->state == RS_FINAL || r->state == RS_ACTIVE;
}

static void
send_event(RDP *r, int type, int a, int b, int c)
{
	PKT k;

	if (!active(r))
		return;
	start_data(&k);
	p16(&k, 1);			/* numberEvents */
	p16(&k, 0);
	p32(&k, 0);			/* eventTime */
	p16(&k, type);
	p16(&k, a);
	p16(&k, b);
	p16(&k, c);
	send_data(r, &k, 28);
}

void
rdp_key(RDP *r, int flags, int scancode)
{
	send_event(r, 4, flags, scancode, 0);
}

void
rdp_mouse(RDP *r, int flags, int x, int y)
{
	send_event(r, 0x8001, flags, x & 0xFFFF, y & 0xFFFF);
}

void
rdp_sync(RDP *r, int toggles)
{
	send_event(r, 0, 0, toggles, 0);
}

void
rdp_refresh(RDP *r, int x, int y, int w, int h)
{
	PKT k;

	if (!active(r) || w <= 0 || h <= 0)
		return;
	start_data(&k);
	p8(&k, 1);
	pzero(&k, 3);
	p16(&k, x);
	p16(&k, y);
	p16(&k, x + w - 1);
	p16(&k, y + h - 1);
	send_data(r, &k, 33);
}

void
rdp_suppress(RDP *r, int allow)
{
	PKT k;

	if (!active(r))
		return;
	start_data(&k);
	p8(&k, allow ? 1 : 0);
	pzero(&k, 3);
	if (allow) {			/* as every client: width, height */
		p16(&k, 0);
		p16(&k, 0);
		p16(&k, r->fb.w);
		p16(&k, r->fb.h);
	}
	send_data(r, &k, 35);
}

/* the user ends the session */
void
rdp_close(RDP *r)
{
	r->bye = 1;
	if (r->state >= RS_JOIN && r->state != RS_DONE)
		send_dpum(r, 3);	/* user requested */
	rdp_fail(r, "");
}
