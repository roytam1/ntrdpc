/*
 * nla.c - NLA: the logon before the session, CredSSP (MS-CSSP) with NTLMv2
 * (MS-NLMP), inside TLS (tls.c).  Windows Vista and later ask for it by
 * default.  The NTLM tokens go raw, not wrapped in SPNEGO: Windows takes
 * both.  MD4, MD5, HMAC-MD5 and RC4 are in crypt.c; SHA-256 is BearSSL's.
 *
 * The exchange (client = us):
 *   1. client: NEGOTIATE
 *   2. server: CHALLENGE                (and its CredSSP version)
 *   3. client: AUTHENTICATE + pubKeyAuth (the TLS key, sealed)
 *   4. server: pubKeyAuth                (proves it saw the same key)
 *   5. client: authInfo                  (user, domain, password, sealed)
 * Then the RDP connection goes on as with TLS alone.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ntrdpc.h"
#include "bearssl.h"

#define CSSP_VERSION	6

/* NTLM negotiate flags */
#define NF_UNICODE	0x00000001UL
#define NF_REQ_TARGET	0x00000004UL
#define NF_SIGN		0x00000010UL
#define NF_SEAL		0x00000020UL
#define NF_NTLM		0x00000200UL
#define NF_ALWAYS_SIGN	0x00008000UL
#define NF_ESS		0x00080000UL	/* extended session security */
#define NF_VERSION	0x02000000UL
#define NF_128		0x20000000UL
#define NF_KEY_EXCH	0x40000000UL
#define NF_56		0x80000000UL
#define NF_OURS		(NF_UNICODE | NF_REQ_TARGET | NF_SIGN | NF_SEAL | \
			 NF_NTLM | NF_ALWAYS_SIGN | NF_ESS | NF_VERSION | \
			 NF_128 | NF_KEY_EXCH | NF_56)


static u32
get32(const u8 *p)
{
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static void
put32(u8 *p, u32 v)
{
	p[0] = (u8)v;
	p[1] = (u8)(v >> 8);
	p[2] = (u8)(v >> 16);
	p[3] = (u8)(v >> 24);
}


/*
 * The NLA state.
 */

struct NLA {
	int step;			/* the server message we wait for: 2, 4 */
	int version;			/* the server's CredSSP version */
	u8 neg[40];			/* our NEGOTIATE, for the MIC */
	u8 *chal;			/* the server's CHALLENGE */
	int challen;
	u32 flags;			/* agreed NTLM flags */
	u8 nonce[32];			/* CredSSP v5+ */
	u8 sign_c[16], sign_s[16];	/* signing keys: to the server, back */
	RC4 seal_c, seal_s;		/* sealing: to the server, back */
	u32 seq_c, seq_s;
	u8 user[130], domain[130];	/* UTF-16LE */
	int userlen, domainlen;
};

/* Latin-1 to UTF-16LE; upper: also to upper case (as Windows does) */
static int
wide(u8 *out, const char *s, int n, int upper)
{
	int k = 0, c;

	while (n-- > 0 && *s) {
		c = (u8)*s++;
		if (upper && ((c >= 'a' && c <= 'z') ||
			      (c >= 0xE0 && c <= 0xFE && c != 0xF7)))
			c -= 0x20;
		out[k++] = (u8)c;
		out[k++] = 0;
	}
	return k;
}


/*
 * DER, as CredSSP needs it.
 */

static int
dlen(int n)			/* bytes of a tag and a length */
{
	return n < 0x80 ? 2 : n < 0x100 ? 3 : 4;
}

static u8 *
dhead(u8 *p, int tag, int n)
{
	*p++ = (u8)tag;
	if (n >= 0x100) {
		*p++ = 0x82;
		*p++ = (u8)(n >> 8);
	} else if (n >= 0x80) {
		*p++ = 0x81;
	}
	*p++ = (u8)n;
	return p;
}

/* [ctag] OCTET STRING: the size, or written at p when p is set */
static int
dfield(u8 *p, int ctag, const u8 *d, int n)
{
	int in = dlen(n) + n;

	if (p) {
		p = dhead(p, ctag, in);
		p = dhead(p, 0x04, n);
		memcpy(p, d, (size_t)n);
	}
	return dlen(in) + in;
}

/* a TSRequest; returns its length in out (at least 64 + the fields) */
static int
ts_request(u8 *out, const u8 *tok, int toklen, const u8 *auth, int authlen,
	   const u8 *pka, int pkalen, const u8 *nonce)
{
	int body, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
	u8 *p;

	body = 5;				/* [0] INTEGER version */
	if (tok) {
		t1 = dlen(toklen) + toklen;	/* OCTET STRING */
		t2 = dlen(t1) + t1;		/* [0] */
		t3 = dlen(t2) + t2;		/* SEQUENCE */
		t4 = dlen(t3) + t3;		/* SEQUENCE OF */
		body += dlen(t4) + t4;		/* [1] */
	}
	if (auth)
		body += dfield(NULL, 0xA2, auth, authlen);
	if (pka)
		body += dfield(NULL, 0xA3, pka, pkalen);
	if (nonce)
		body += dfield(NULL, 0xA5, nonce, 32);
	p = dhead(out, 0x30, body);
	*p++ = 0xA0;
	*p++ = 3;
	*p++ = 0x02;
	*p++ = 1;
	*p++ = CSSP_VERSION;
	if (tok) {
		p = dhead(p, 0xA1, t4);
		p = dhead(p, 0x30, t3);
		p = dhead(p, 0x30, t2);
		p = dhead(p, 0xA0, t1);
		p = dhead(p, 0x04, toklen);
		memcpy(p, tok, (size_t)toklen);
		p += toklen;
	}
	if (auth)
		p += dfield(p, 0xA2, auth, authlen);
	if (pka)
		p += dfield(p, 0xA3, pka, pkalen);
	if (nonce)
		p += dfield(p, 0xA5, nonce, 32);
	return (int)(p - out);
}

/* reads a tag and a length; moves *p to the contents; -1 if bad */
static long
dread(const u8 **p, const u8 *end, int tag)
{
	long n;
	int k;

	if (end - *p < 2 || **p != tag)
		return -1;
	(*p)++;
	n = *(*p)++;
	if (n & 0x80) {
		k = (int)(n & 0x7F);
		if (k < 1 || k > 3 || end - *p < k)
			return -1;
		n = 0;
		while (k-- > 0)
			n = n << 8 | *(*p)++;
	}
	return end - *p < n ? -1 : n;
}

typedef struct {
	long version;
	const u8 *tok, *pka;
	int toklen, pkalen;
	u32 error;
} TSREQ;

static u32
dint(const u8 *p, long n)
{
	u32 v = 0;

	while (n-- > 0)
		v = v << 8 | *p++;
	return v;
}

static int
ts_parse(const u8 *p, int n, TSREQ *t)
{
	const u8 *end = p + n, *q, *e;
	long len, k;

	memset(t, 0, sizeof(TSREQ));
	if (dread(&p, end, 0x30) < 0)
		return 0;
	while (end - p >= 2) {
		int tag = *p;

		len = dread(&p, end, tag);
		if (len < 0)
			return 0;
		q = p;
		e = p + len;
		switch (tag) {
		case 0xA0:			/* version */
			k = dread(&q, e, 0x02);
			if (k < 1 || k > 4)
				return 0;
			t->version = (long)dint(q, k);
			break;
		case 0xA1:			/* negoTokens */
			if (dread(&q, e, 0x30) < 0 || dread(&q, e, 0x30) < 0 ||
			    dread(&q, e, 0xA0) < 0 ||
			    (k = dread(&q, e, 0x04)) < 0)
				return 0;
			t->tok = q;
			t->toklen = (int)k;
			break;
		case 0xA3:			/* pubKeyAuth */
			if ((k = dread(&q, e, 0x04)) < 0)
				return 0;
			t->pka = q;
			t->pkalen = (int)k;
			break;
		case 0xA4:			/* errorCode */
			k = dread(&q, e, 0x02);
			if (k < 1 || k > 5)
				return 0;
			t->error = dint(q, k);
			break;
		}
		p = e;
	}
	return 1;
}


/*
 * NTLM.
 */

static const u8 ntlm_version[8] = { 6, 1, 0xB1, 0x1D, 0, 0, 0, 15 };

static void
send_ts(RDP *r, const u8 *tok, int toklen, const u8 *auth, int authlen,
	const u8 *pka, int pkalen, const u8 *nonce)
{
	u8 *b;
	int n = 64 + toklen + authlen + pkalen + 64;

	b = (u8 *)malloc((size_t)n);
	if (!b) {
		rdp_fail(r, "Out of memory.");
		return;
	}
	n = ts_request(b, tok, toklen, auth, authlen, pka, pkalen, nonce);
	rdp_out(r, b, n);
	memset(b, 0, (size_t)n);
	free(b);
}

/* seals a message for the server: 16 bytes of signature, then the text */
static void
seal(NLA *a, const u8 *msg, int n, u8 *out)
{
	HMAC h;
	u8 seq[4], mac[16];

	rc4(&a->seal_c, msg, out + 16, n);
	put32(seq, a->seq_c);
	hmac_init(&h, a->sign_c);
	md_update(&h.in, seq, 4);
	md_update(&h.in, msg, n);
	hmac_final(&h, mac);
	put32(out, 1);
	if (a->flags & NF_KEY_EXCH)
		rc4(&a->seal_c, mac, out + 4, 8);
	else
		memcpy(out + 4, mac, 8);
	put32(out + 12, a->seq_c);
	a->seq_c++;
}

/* unseals a message from the server in place: the text, or NULL */
static u8 *
unseal(NLA *a, u8 *p, int n, int *len)
{
	HMAC h;
	u8 seq[4], mac[16], chk[8];

	if (n < 16 || get32(p) != 1 || get32(p + 12) != a->seq_s)
		return NULL;
	rc4(&a->seal_s, p + 16, p + 16, n - 16);
	if (a->flags & NF_KEY_EXCH)
		rc4(&a->seal_s, p + 4, chk, 8);
	else
		memcpy(chk, p + 4, 8);
	put32(seq, a->seq_s);
	hmac_init(&h, a->sign_s);
	md_update(&h.in, seq, 4);
	md_update(&h.in, p + 16, n - 16);
	hmac_final(&h, mac);
	if (memcmp(mac, chk, 8) != 0)
		return NULL;
	a->seq_s++;
	*len = n - 16;
	return p + 16;
}

/* key = MD5(base, magic and its 0) */
static void
derive_n(const u8 *base, int n, const char *magic, u8 *out)
{
	MD m;

	md_init(&m, MD_MD5);
	md_update(&m, base, n);
	md_update(&m, (const u8 *)magic, (int)strlen(magic) + 1);
	md_final(&m, out);
}

static void
derive(const u8 *base, const char *magic, u8 *out)
{
	derive_n(base, 16, magic, out);
}

/* the binding of CredSSP v5 and later: SHA-256(magic, nonce, key) */
static void
bind_hash(const char *magic, const u8 *nonce, const u8 *key, int keylen,
	  u8 *out)
{
	br_sha256_context c;

	br_sha256_init(&c);
	br_sha256_update(&c, magic, strlen(magic) + 1);
	br_sha256_update(&c, nonce, 32);
	br_sha256_update(&c, key, (size_t)keylen);
	br_sha256_out(&c, out);
}

void
nla_start(RDP *r)
{
	NLA *a;
	u8 *m;
	const char *s = r->opt.user, *bs;
	int ulen;

	a = (NLA *)calloc(1, sizeof(NLA));
	if (!a) {
		rdp_fail(r, "Out of memory.");
		return;
	}
	r->nla = a;
	/* DOMAIN\user, else the domain field */
	bs = strchr(s, '\\');
	if (bs) {
		a->domainlen = wide(a->domain, s, (int)(bs - s), 0);
		s = bs + 1;
	} else {
		a->domainlen = wide(a->domain, r->opt.domain, 64, 0);
	}
	ulen = (int)strlen(s);
	a->userlen = wide(a->user, s, ulen, 0);

	m = a->neg;
	memcpy(m, "NTLMSSP", 8);
	put32(m + 8, 1);
	put32(m + 12, NF_OURS);
	memset(m + 16, 0, 16);		/* no domain, no workstation */
	memcpy(m + 32, ntlm_version, 8);
	a->step = 2;
	r->state = RS_NLA;
	ui_state(r);
	send_ts(r, a->neg, 40, NULL, 0, NULL, 0, NULL);
}

void
nla_free(NLA *a)
{
	if (!a)
		return;
	if (a->chal)
		free(a->chal);
	memset(a, 0, sizeof(NLA));
	free(a);
}

/* the field of a message: length and offset; 0 if outside */
static const u8 *
mfield(const u8 *m, int n, int at, int *len)
{
	long off;

	if (at + 8 > n)
		return NULL;
	*len = m[at] | m[at + 1] << 8;
	off = (long)get32(m + at + 4);
	if (off < 0 || off > n || *len > n - off)
		return NULL;
	return m + off;
}

/* the third message: AUTHENTICATE with the sealed TLS key */
static void
authenticate(RDP *r, NLA *a)
{
	const u8 *ti, *p, *ts = NULL, *spk;
	u8 pw[130], nthash[16], v2[16], cc[8], proof[16], sbk[16], esk[16];
	u8 key[16], hash[32], *blob, *msg, *pka, *q;
	u8 ws[34];
	int tilen, bloblen, msglen, wslen, pklen, spklen, n, flags_av = 0;
	HMAC h;
	RC4 k;

	ti = mfield(a->chal, a->challen, 40, &tilen);
	if (!ti || !(a->flags & NF_ESS)) {
		rdp_fail(r, "The server's NTLM challenge is not usable.");
		return;
	}
	if (!tls_server_key(r, &spk, &spklen)) {
		rdp_fail(r, "Cannot read the server's TLS key.");
		return;
	}

	/* NTOWFv2 = HMAC(MD4(password), UPPER(user) domain) */
	n = wide(pw, r->opt.password, 64, 0);
	md_sum(MD_MD4, pw, n, nthash);
	memset(pw, 0, sizeof(pw));
	hmac_init(&h, nthash);
	{
		const char *s = r->opt.user, *bs = strchr(s, '\\');
		u8 up[130];
		int ul;

		ul = wide(up, bs ? bs + 1 : s, 64, 1);
		md_update(&h.in, up, ul);
	}
	md_update(&h.in, a->domain, a->domainlen);
	hmac_final(&h, v2);
	memset(nthash, 0, sizeof(nthash));

	/* the client blob: our AV pairs are the server's plus MsvAvFlags
	   (a MIC follows) and empty channel bindings */
	blob = (u8 *)malloc((size_t)(tilen + 64));
	if (!blob) {
		rdp_fail(r, "Out of memory.");
		return;
	}
	rdp_random(r, cc, 8);
	q = blob;
	*q++ = 1;
	*q++ = 1;
	memset(q, 0, 6);
	q += 6;
	for (p = ti; p + 4 <= ti + tilen; ) {
		int id = p[0] | p[1] << 8, len = p[2] | p[3] << 8;

		if (p + 4 + len > ti + tilen || id == 0)
			break;
		if (id == 7 && len == 8)
			ts = p + 4;		/* MsvAvTimestamp */
		p += 4 + len;
	}
	if (ts)
		memcpy(q, ts, 8);
	else
		memset(q, 0, 8);
	q += 8;
	memcpy(q, cc, 8);
	q += 8;
	memset(q, 0, 4);
	q += 4;
	for (p = ti; p + 4 <= ti + tilen; ) {
		int id = p[0] | p[1] << 8, len = p[2] | p[3] << 8;

		if (p + 4 + len > ti + tilen || id == 0)
			break;
		memcpy(q, p, (size_t)(4 + len));
		if (id == 6 && len == 4) {	/* MsvAvFlags: add MIC */
			put32(q + 4, get32(p + 4) | 2);
			flags_av = 1;
		}
		q += 4 + len;
		p += 4 + len;
	}
	if (!flags_av) {
		put32(q, 6 | 4UL << 16);
		put32(q + 4, 2);
		q += 8;
	}
	put32(q, 10 | 16UL << 16);		/* MsvAvChannelBindings */
	memset(q + 4, 0, 16);
	q += 20;
	memset(q, 0, 8);			/* MsvAvEOL, then 4 zeros */
	q += 8;
	bloblen = (int)(q - blob);

	/* NTProofStr and the keys */
	hmac_init(&h, v2);
	md_update(&h.in, a->chal + 24, 8);
	md_update(&h.in, blob, bloblen);
	hmac_final(&h, proof);
	hmac_md5(v2, proof, 16, sbk);
	if (a->flags & NF_KEY_EXCH) {
		rdp_random(r, esk, 16);
		rc4_init(&k, sbk, 16);
		rc4(&k, esk, key, 16);		/* EncryptedRandomSessionKey */
	} else {
		memcpy(esk, sbk, 16);
	}

	/* the message */
	wslen = wide(ws, r->opt.client, 15, 0);
	msglen = 88 + 24 + 16 + bloblen + a->domainlen + a->userlen + wslen +
		 16;
	msg = (u8 *)calloc(1, (size_t)msglen);
	if (!msg) {
		free(blob);
		rdp_fail(r, "Out of memory.");
		return;
	}
	memcpy(msg, "NTLMSSP", 8);
	put32(msg + 8, 3);
	n = 88;
#define FIELD(at, len) \
	(msg[at] = msg[at + 2] = (u8)(len), \
	 msg[at + 1] = msg[at + 3] = (u8)((len) >> 8), \
	 put32(msg + (at) + 4, (u32)n), n += (len))
	FIELD(12, 24);				/* LmChallengeResponse: 0s */
	memcpy(msg + n, proof, 16);
	memcpy(msg + n + 16, blob, (size_t)bloblen);
	FIELD(20, 16 + bloblen);		/* NtChallengeResponse */
	memcpy(msg + n, a->domain, (size_t)a->domainlen);
	FIELD(28, a->domainlen);
	memcpy(msg + n, a->user, (size_t)a->userlen);
	FIELD(36, a->userlen);
	memcpy(msg + n, ws, (size_t)wslen);
	FIELD(44, wslen);
	if (a->flags & NF_KEY_EXCH) {
		memcpy(msg + n, key, 16);
		FIELD(52, 16);
	} else {
		FIELD(52, 0);
	}
#undef FIELD
	put32(msg + 60, a->flags);
	memcpy(msg + 64, ntlm_version, 8);
	msglen = n;
	free(blob);

	/* MIC = HMAC(ExportedSessionKey, the three messages) */
	hmac_init(&h, esk);
	md_update(&h.in, a->neg, 40);
	md_update(&h.in, a->chal, a->challen);
	md_update(&h.in, msg, msglen);
	hmac_final(&h, msg + 72);

	derive(esk, "session key to client-to-server signing key magic "
	       "constant", a->sign_c);
	derive(esk, "session key to server-to-client signing key magic "
	       "constant", a->sign_s);
	/* the sealing keys use 16, 7 or 5 bytes of the session key */
	n = a->flags & NF_128 ? 16 : a->flags & NF_56 ? 7 : 5;
	derive_n(esk, n, "session key to client-to-server sealing key magic "
		 "constant", key);
	rc4_init(&a->seal_c, key, 16);
	derive_n(esk, n, "session key to server-to-client sealing key magic "
		 "constant", key);
	rc4_init(&a->seal_s, key, 16);
	memset(esk, 0, sizeof(esk));
	memset(sbk, 0, sizeof(sbk));
	memset(v2, 0, sizeof(v2));

	/* pubKeyAuth: the key (v2 - v4) or its hash (v5 +), sealed */
	if (a->version >= 5) {
		rdp_random(r, a->nonce, 32);
		bind_hash("CredSSP Client-To-Server Binding Hash", a->nonce,
			  spk, spklen, hash);
		pklen = 32;
		pka = (u8 *)malloc(16 + 32);
		if (pka)
			seal(a, hash, 32, pka);
	} else {
		pklen = spklen;
		pka = (u8 *)malloc((size_t)(16 + spklen));
		if (pka)
			seal(a, spk, spklen, pka);
	}
	if (!pka) {
		free(msg);
		rdp_fail(r, "Out of memory.");
		return;
	}
	send_ts(r, msg, msglen, NULL, 0, pka, 16 + pklen,
		a->version >= 5 ? a->nonce : NULL);
	free(msg);
	free(pka);
	a->step = 4;
}

/* the fifth message: user, domain and password, sealed */
static void
credentials(RDP *r, NLA *a)
{
	u8 pw[130], *c, *out;
	int pwlen, n, t1, t2, t3, cl;
	u8 *p;

	pwlen = wide(pw, r->opt.password, 64, 0);
	/* TSPasswordCreds: SEQUENCE { [0] domain, [1] user, [2] password } */
	t1 = dfield(NULL, 0xA0, a->domain, a->domainlen) +
	     dfield(NULL, 0xA1, a->user, a->userlen) +
	     dfield(NULL, 0xA2, pw, pwlen);
	t2 = dlen(t1) + t1;
	/* TSCredentials: SEQUENCE { [0] INTEGER 1, [1] OCTET STRING } */
	t3 = 5 + dfield(NULL, 0xA1, NULL, t2);
	cl = dlen(t3) + t3;
	c = (u8 *)malloc((size_t)(cl + 16));
	out = (u8 *)malloc((size_t)(cl + 16));
	if (!c || !out) {
		if (c)
			free(c);
		if (out)
			free(out);
		rdp_fail(r, "Out of memory.");
		return;
	}
	p = dhead(c, 0x30, t3);
	*p++ = 0xA0;
	*p++ = 3;
	*p++ = 0x02;
	*p++ = 1;
	*p++ = 1;			/* password */
	p = dhead(p, 0xA1, dlen(t2) + t2);
	p = dhead(p, 0x04, t2);
	p = dhead(p, 0x30, t1);
	p += dfield(p, 0xA0, a->domain, a->domainlen);
	p += dfield(p, 0xA1, a->user, a->userlen);
	p += dfield(p, 0xA2, pw, pwlen);
	n = (int)(p - c);
	memset(pw, 0, sizeof(pw));
	seal(a, c, n, out);
	memset(c, 0, (size_t)n);
	send_ts(r, NULL, 0, out, n + 16, NULL, 0, NULL);
	memset(out, 0, (size_t)(n + 16));
	free(c);
	free(out);
}

static const char *
nt_status_text(u32 code)
{
	switch (code) {
	case 0xC000006DUL:		/* STATUS_LOGON_FAILURE */
	case 0xC000006AUL:		/* STATUS_WRONG_PASSWORD */
	case 0xC0000064UL:		/* STATUS_NO_SUCH_USER */
		return "Wrong user name or password.";
	case 0xC0000071UL:		/* STATUS_PASSWORD_EXPIRED */
	case 0xC0000224UL:		/* STATUS_PASSWORD_MUST_CHANGE */
		return "The password has expired. Change it on the server.";
	case 0xC0000072UL:		/* STATUS_ACCOUNT_DISABLED */
		return "The account is disabled.";
	case 0xC0000234UL:		/* STATUS_ACCOUNT_LOCKED_OUT */
		return "The account is locked.";
	case 0xC000015BUL:		/* STATUS_LOGON_TYPE_NOT_GRANTED */
		return "This user may not log on through Remote Desktop.";
	case 0xC000006EUL:		/* STATUS_ACCOUNT_RESTRICTION */
		return "This account may not log on: an empty password?";
	}
	return NULL;
}

/* one TSRequest from the server */
void
nla_input(RDP *r, u8 *p, int n)
{
	NLA *a = r->nla;
	TSREQ t;
	const u8 *spk;
	u8 *m, hash[32];
	int len, spklen;
	char buf[80];
	const char *s;

	if (!ts_parse(p, n, &t)) {
		rdp_fail(r, "The server sent a bad NLA message.");
		return;
	}
	if (t.error) {
		s = nt_status_text(t.error);
		if (!s) {
			sprintf(buf, "The server refused the logon (NLA, "
				"error 0x%08lX).", (unsigned long)t.error);
			s = buf;
		}
		rdp_fail(r, s);
		return;
	}
	if (a->step == 2) {
		if (!t.tok || t.toklen < 48 || memcmp(t.tok, "NTLMSSP", 8) ||
		    get32(t.tok + 8) != 2) {
			rdp_fail(r, "The server does not offer NTLM for NLA.");
			return;
		}
		a->version = (int)t.version;
		a->chal = (u8 *)malloc((size_t)t.toklen);
		if (!a->chal) {
			rdp_fail(r, "Out of memory.");
			return;
		}
		memcpy(a->chal, t.tok, (size_t)t.toklen);
		a->challen = t.toklen;
		a->flags = get32(a->chal + 20);
		authenticate(r, a);
		return;
	}
	if (a->step == 4) {
		if (!t.pka || !(m = unseal(a, (u8 *)t.pka, t.pkalen, &len)) ||
		    !tls_server_key(r, &spk, &spklen)) {
			rdp_fail(r, "The server failed the NLA key check.");
			return;
		}
		if (a->version >= 5) {
			bind_hash("CredSSP Server-To-Client Binding Hash",
				  a->nonce, spk, spklen, hash);
			if (len != 32 || memcmp(m, hash, 32) != 0) {
				rdp_fail(r, "The server failed the NLA key "
					 "check.");
				return;
			}
		} else if (len != spklen || m[0] != (u8)(spk[0] + 1) ||
			   memcmp(m + 1, spk + 1, (size_t)(spklen - 1)) != 0) {
			rdp_fail(r, "The server failed the NLA key check.");
			return;
		}
		credentials(r, a);
		a->step = 0;
		if (r->state != RS_DONE)
			rdp_nla_done(r);
		return;
	}
}
