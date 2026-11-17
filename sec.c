/*
 * sec.c - Standard RDP Security (MS-RDPBCGR 5.3): RC4 with 40, 56 or
 * 128-bit keys, as Windows 2000, XP and Server 2003 use it, and every
 * Windows server when TLS is off.  Also the licensing exchange (MS-RDPELE),
 * with RC4 security and with TLS.
 *
 *   1. The server's SC_SECURITY block: method, level, its random, and its
 *      certificate (proprietary or X.509), so its RSA key.
 *   2. Client: the Security Exchange PDU, our random encrypted with RSA.
 *   3. Both sides make the same RC4 and MAC keys from the two randoms.
 *   4. Every PDU then carries a MAC and is RC4-encrypted.  After 4096 PDUs
 *      in one direction, the key of that direction changes.
 *
 * RSA is BearSSL's, raw (RDP pads nothing).  MD5, SHA-1 and RC4 are in
 * crypt.c.  Numbers in RDP's certificates and randoms are little-endian.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ntrdpc.h"
#include "bearssl.h"

#define PLATFORM_ID	0x04010000UL	/* Windows NT, a Microsoft client */

typedef struct {
	u8 n[512];			/* modulus, big-endian */
	int nlen;			/* 0: none */
	u8 e[4];			/* exponent, big-endian */
	int elen;
} RSAKEY;

struct SEC {
	int method;			/* 1 = 40-bit, 2 = 128-bit, 8 = 56-bit;
					   0 = licensing only */
	int keylen;			/* RC4 key bytes: 8 or 16 */
	u8 srand[32];			/* the server's random */
	RSAKEY key;			/* the server's key */
	int on;				/* RC4 runs */
	u8 mackey[16];
	u8 enc0[16], enc[16];		/* to the server: first key, now */
	u8 dec0[16], dec[16];		/* from the server */
	RC4 encrc4, decrc4;
	int encuse, decuse;		/* PDUs with the key now */
	int lic;			/* the licensing keys are made */
	u8 lmac[16];			/* licensing: MAC salt key */
	u8 lkey[16];			/* licensing: RC4 key */
};

static u32
get32(const u8 *p)
{
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static int
get16(const u8 *p)
{
	return p[0] | p[1] << 8;
}

static void
put16(u8 *p, int v)
{
	p[0] = (u8)v;
	p[1] = (u8)(v >> 8);
}

static void
put32(u8 *p, u32 v)
{
	put16(p, (int)(v & 0xFFFF));
	put16(p + 2, (int)(v >> 16));
}

static SEC *
sec_get(RDP *r)
{
	if (!r->sec)
		r->sec = (SEC *)calloc(1, sizeof(SEC));
	if (!r->sec)
		rdp_fail(r, "Out of memory.");
	return r->sec;
}

void
sec_free(SEC *s)
{
	if (s) {
		memset(s, 0, sizeof(SEC));
		free(s);
	}
}

int
sec_on(RDP *r)
{
	return r->sec && r->sec->on;
}


/*
 * The server's RSA key.
 */

/* n big-endian, without leading zeros */
static int
set_n(RSAKEY *k, const u8 *n, int len)
{
	while (len > 0 && *n == 0) {
		n++;
		len--;
	}
	if (len < 32 + 1 || len > (int)sizeof(k->n))
		return 0;
	memcpy(k->n, n, (size_t)len);
	k->nlen = len;
	return 1;
}

/* the DER RSAPublicKey of an X.509 certificate */
static int
x509_key(const u8 *cert, int clen, RSAKEY *k)
{
	const u8 *p, *end, *e;
	long n, en;

	if (!cert_key(cert, clen, &p, &clen))
		return 0;
	end = p + clen;
	if (der_read(&p, end, 0x30) < 0 || (n = der_read(&p, end, 0x02)) < 1)
		return 0;
	e = p + n;
	if ((en = der_read(&e, end, 0x02)) < 1)
		return 0;
	while (en > 1 && *e == 0) {
		e++;
		en--;
	}
	if (en > 4 || !set_n(k, p, (int)n))
		return 0;
	memcpy(k->e, e, (size_t)en);
	k->elen = (int)en;
	return 1;
}

/* a server certificate (MS-RDPBCGR 2.2.1.4.3.1): proprietary (an RSA1
   key blob, little-endian), or a chain of X.509 certificates whose last
   one is the server's */
static int
read_cert(const u8 *p, int n, RSAKEY *k)
{
	u8 be[512];
	u32 ver, count, len, bits, i;
	const u8 *end = p + n, *last = NULL;
	int mlen, j;

	if (n < 8)
		return 0;
	ver = get32(p) & 0x7FFFFFFFUL;
	if (ver == 1) {
		if (n < 36 + 8 || get16(p + 12) != 6 ||
		    get32(p + 16) != 0x31415352UL)	/* "RSA1" */
			return 0;
		bits = get32(p + 24);
		mlen = (int)((bits + 7) / 8);
		if (bits < 256 || mlen > (int)sizeof(be) || mlen > n - 36 ||
		    (u32)mlen > get32(p + 20))
			return 0;
		for (j = 0; j < mlen; j++)
			be[j] = p[36 + mlen - 1 - j];
		if (!set_n(k, be, mlen))
			return 0;
		put32(be, get32(p + 32));	/* the exponent */
		for (j = 0; j < 4; j++)
			k->e[j] = be[3 - j];
		k->elen = 4;
		return 1;
	}
	if (ver != 2)
		return 0;
	count = get32(p + 4);
	p += 8;
	for (i = 0; i < count; i++) {
		if (end - p < 4)
			return 0;
		len = get32(p);
		p += 4;
		if (len > (u32)(end - p))
			return 0;
		last = p;
		n = (int)len;
		p += len;
	}
	return last && x509_key(last, n, k);
}

/* raw RSA of a little-endian number, as RDP does it: out gets the result
   little-endian, then 8 zero bytes; returns their count, or 0 */
static int
rsa_le(const RSAKEY *k, const u8 *in, int inlen, u8 *out)
{
	br_rsa_public_key pk;
	u8 x[512];
	int i;

	if (k->nlen <= inlen)
		return 0;
	memset(x, 0, (size_t)k->nlen);
	for (i = 0; i < inlen; i++)
		x[k->nlen - 1 - i] = in[i];
	pk.n = (unsigned char *)k->n;
	pk.nlen = (size_t)k->nlen;
	pk.e = (unsigned char *)k->e;
	pk.elen = (size_t)k->elen;
	if (!br_rsa_i15_public(x, (size_t)k->nlen, &pk))
		return 0;
	for (i = 0; i < k->nlen; i++)
		out[i] = x[k->nlen - 1 - i];
	memset(out + k->nlen, 0, 8);
	return k->nlen + 8;
}

/* SC_SECURITY (MS-RDPBCGR 2.2.1.4.3), the whole block; 0 = failed */
int
sec_server_data(RDP *r, const u8 *p, int n)
{
	SEC *s;
	u32 method, level, rlen, clen;

	if (n < 12)
		return 1;
	method = get32(p + 4);
	level = get32(p + 8);
	if (!method && !level)
		return 1;		/* no encryption */
	if (method != 1 && method != 2 && method != 8) {
		rdp_fail(r, method == 0x10 ? "The server wants FIPS "
			 "encryption. ntrdpc does not have it." :
			 "The server chose an encryption ntrdpc does not know.");
		return 0;
	}
	if (n < 52)
		goto bad;
	rlen = get32(p + 12);
	clen = get32(p + 16);
	if (rlen != 32 || clen > (u32)(n - 52))
		goto bad;
	if (!(s = sec_get(r)))
		return 0;
	s->method = (int)method;
	s->keylen = method == 2 ? 16 : 8;
	memcpy(s->srand, p + 20, 32);
	if (!read_cert(p + 52, (int)clen, &s->key)) {
		rdp_fail(r, "ntrdpc cannot read the server's certificate.");
		return 0;
	}
	return 1;
bad:
	rdp_fail(r, "The server sent bad security data.");
	return 0;
}


/*
 * Keys (MS-RDPBCGR 5.3.5 - 5.3.7).
 */

/* SaltedHash(S, I) = MD5(S + SHA1(I + S + A + B)) */
static void
salted(const u8 *s, const char *in, const u8 *a, const u8 *b, u8 *out)
{
	MD m;
	u8 sha[20];

	md_init(&m, MD_SHA1);
	md_update(&m, (const u8 *)in, (int)strlen(in));
	md_update(&m, s, 48);
	md_update(&m, a, 32);
	md_update(&m, b, 32);
	md_final(&m, sha);
	md_init(&m, MD_MD5);
	md_update(&m, s, 48);
	md_update(&m, sha, 20);
	md_final(&m, out);
}

/* 48 bytes: SaltedHash with "A", "BB", "CCC" or "X", "YY", "ZZZ" */
static void
hash48(const u8 *s, int x, const u8 *a, const u8 *b, u8 *out)
{
	salted(s, x ? "X" : "A", a, b, out);
	salted(s, x ? "YY" : "BB", a, b, out + 16);
	salted(s, x ? "ZZZ" : "CCC", a, b, out + 32);
}

/* FinalHash(K) = MD5(K + ClientRandom + ServerRandom) */
static void
final_hash(const u8 *k, const u8 *cr, const u8 *sr, u8 *out)
{
	MD m;

	md_init(&m, MD_MD5);
	md_update(&m, k, 16);
	md_update(&m, cr, 32);
	md_update(&m, sr, 32);
	md_final(&m, out);
}

/* the 40 and 56-bit keys: 8 bytes, the first ones fixed */
static void
salt_key(const SEC *s, u8 *k)
{
	if (s->method == 1) {
		k[0] = 0xD1;
		k[1] = 0x26;
		k[2] = 0x9E;
	} else if (s->method == 8) {
		k[0] = 0xD1;
	}
}

/* MAC = MD5(K + pad2 + SHA1(K + pad1 + length + data)); 16 bytes */
static void
mac(const u8 *key, int keylen, const u8 *d, int n, u8 *out)
{
	u8 pad[48], len[4], sha[20];
	MD m;

	memset(pad, 0x36, 40);
	put32(len, (u32)n);
	md_init(&m, MD_SHA1);
	md_update(&m, key, keylen);
	md_update(&m, pad, 40);
	md_update(&m, len, 4);
	md_update(&m, d, n);
	md_final(&m, sha);
	memset(pad, 0x5C, 48);
	md_init(&m, MD_MD5);
	md_update(&m, key, keylen);
	md_update(&m, pad, 48);
	md_update(&m, sha, 20);
	md_final(&m, out);
}

static void
make_keys(SEC *s, const u8 *cr)
{
	u8 pre[48], master[48], blob[48];

	memcpy(pre, cr, 24);
	memcpy(pre + 24, s->srand, 24);
	hash48(pre, 0, cr, s->srand, master);
	hash48(master, 1, cr, s->srand, blob);
	memcpy(s->mackey, blob, 16);
	final_hash(blob + 16, cr, s->srand, s->dec0);	/* the server's */
	final_hash(blob + 32, cr, s->srand, s->enc0);	/* ours */
	salt_key(s, s->mackey);
	salt_key(s, s->dec0);
	salt_key(s, s->enc0);
	memcpy(s->enc, s->enc0, 16);
	memcpy(s->dec, s->dec0, 16);
	rc4_init(&s->encrc4, s->enc, s->keylen);
	rc4_init(&s->decrc4, s->dec, s->keylen);
	s->encuse = s->decuse = 0;
	memset(pre, 0, sizeof(pre));
	memset(master, 0, sizeof(master));
	memset(blob, 0, sizeof(blob));
}

/* a new key after 4096 PDUs */
static void
update_key(const SEC *s, const u8 *first, u8 *now, RC4 *rc)
{
	u8 pad[48], sha[20], tmp[16];
	MD m;
	RC4 t;

	memset(pad, 0x36, 40);
	md_init(&m, MD_SHA1);
	md_update(&m, first, s->keylen);
	md_update(&m, pad, 40);
	md_update(&m, now, s->keylen);
	md_final(&m, sha);
	memset(pad, 0x5C, 48);
	md_init(&m, MD_MD5);
	md_update(&m, first, s->keylen);
	md_update(&m, pad, 48);
	md_update(&m, sha, 20);
	md_final(&m, tmp);
	rc4_init(&t, tmp, s->keylen);
	rc4(&t, tmp, now, s->keylen);
	salt_key(s, now);
	rc4_init(rc, now, s->keylen);
}

/* the Security Exchange PDU, then the keys; nothing without encryption */
void
sec_exchange(RDP *r)
{
	SEC *s = r->sec;
	u8 cr[32], b[32 + 4 + 512 + 8];
	int n;

	if (!s || !s->method)
		return;
	rdp_random(r, cr, 32);
	n = rsa_le(&s->key, cr, 32, b + 32 + 4);
	if (!n) {
		rdp_fail(r, "ntrdpc cannot use the server's key.");
		return;
	}
	put32(b + 32, (u32)n);
	rdp_send_sec(r, b + 32, n + 4, SEC_EXCHANGE_PKT);
	make_keys(s, cr);
	memset(cr, 0, sizeof(cr));
	s->on = 1;
}

/* d[0..n): the MAC (8 bytes) to sig, then encrypted in place */
void
sec_encrypt(RDP *r, u8 *d, int n, u8 *sig)
{
	SEC *s = r->sec;
	u8 m[16];

	mac(s->mackey, s->keylen, d, n, m);
	memcpy(sig, m, 8);
	if (s->encuse == 4096) {
		update_key(s, s->enc0, s->enc, &s->encrc4);
		s->encuse = 0;
	}
	rc4(&s->encrc4, d, d, n);
	s->encuse++;
}

/* d[0..n): decrypted in place (the MAC is not checked) */
void
sec_decrypt(RDP *r, u8 *d, int n)
{
	SEC *s = r->sec;

	if (!s || !s->on)
		return;
	if (s->decuse == 4096) {
		update_key(s, s->dec0, s->dec, &s->decrc4);
		s->decuse = 0;
	}
	rc4(&s->decrc4, d, d, n);
	s->decuse++;
}


/*
 * Licensing (MS-RDPELE).  ntrdpc asks for a new license each time and
 * keeps none.
 */

/* a licensing message, b + 32 on, with 32 bytes of room in front */
static void
send_license(RDP *r, u8 *b, int n, int type)
{
	b[32] = (u8)type;
	b[33] = 0x03;			/* PREAMBLE_VERSION_3_0 */
	put16(b + 34, n);
	rdp_send_sec(r, b + 32, n, SEC_LICENSE_PKT);
}

/* SERVER_LICENSE_REQUEST: answer with a CLIENT_NEW_LICENSE_REQUEST */
static void
license_request(RDP *r, const u8 *p, int n)
{
	SEC *s = sec_get(r);
	const u8 *end = p + n, *q;
	u32 len;
	RSAKEY key;
	const RSAKEY *k;
	u8 cr[32], pre[48], master[48], blob[48], b[32 + 4 + 40 + 4 + 520 +
						      4 + 64 + 4 + 16];
	const char *user = r->opt.user[0] ? r->opt.user : "ntrdpc";
	int o, i, ul, ml;

	if (!s)
		return;
	if (n < 32 + 8)
		goto bad;
	q = p + 32 + 4;			/* ServerRandom, dwVersion */
	for (i = 0; i < 2; i++) {	/* company name, product ID */
		if (end - q < 4)
			goto bad;
		len = get32(q);
		q += 4;
		if (len > (u32)(end - q))
			goto bad;
		q += len;
	}
	for (i = 0; i < 2; i++) {	/* KeyExchangeList, ServerCertificate */
		if (end - q < 4)
			goto bad;
		len = (u32)get16(q + 2);
		q += 4;
		if (len > (u32)(end - q))
			goto bad;
		if (i == 0)
			q += len;
	}
	if (len) {
		if (!read_cert(q, (int)len, &key)) {
			rdp_fail(r, "ntrdpc cannot read the server's "
				 "licensing certificate.");
			return;
		}
		k = &key;
	} else if (s->key.nlen) {
		k = &s->key;
	} else {
		rdp_fail(r, "The server sent no key for licensing.");
		return;
	}

	rdp_random(r, cr, 32);
	rdp_random(r, pre, 48);
	o = 32 + 4;
	put32(b + o, 1);		/* KEY_EXCHANGE_ALG_RSA */
	put32(b + o + 4, PLATFORM_ID);
	memcpy(b + o + 8, cr, 32);
	o += 40;
	put16(b + o, 0x0002);		/* BB_RANDOM_BLOB */
	i = rsa_le(k, pre, 48, b + o + 4);
	if (!i) {
		rdp_fail(r, "ntrdpc cannot use the server's licensing key.");
		return;
	}
	put16(b + o + 2, i);
	o += 4 + i;
	ul = (int)strlen(user) + 1;
	ml = (int)strlen(r->opt.client) + 1;
	put16(b + o, 0x000F);		/* BB_CLIENT_USER_NAME_BLOB */
	put16(b + o + 2, ul);
	memcpy(b + o + 4, user, (size_t)ul);
	o += 4 + ul;
	put16(b + o, 0x0010);		/* BB_CLIENT_MACHINE_NAME_BLOB */
	put16(b + o + 2, ml);
	memcpy(b + o + 4, r->opt.client, (size_t)ml);
	o += 4 + ml;
	send_license(r, b, o - 32, 0x13);

	/* the licensing keys (MS-RDPELE 5.1.3): the randoms swap places
	   for the second step */
	hash48(pre, 0, cr, p, master);
	hash48(master, 0, p, cr, blob);
	memcpy(s->lmac, blob, 16);
	final_hash(blob + 16, cr, p, s->lkey);
	s->lic = 1;
	memset(pre, 0, sizeof(pre));
	memset(master, 0, sizeof(master));
	memset(blob, 0, sizeof(blob));
	return;
bad:
	rdp_fail(r, "The server sent a bad license request.");
}

/* SERVER_PLATFORM_CHALLENGE: answer with CLIENT_PLATFORM_CHALLENGE_RESPONSE */
static void
platform_challenge(RDP *r, const u8 *p, int n)
{
	SEC *s = r->sec;
	u8 d[8 + 256 + 20], m[16], b[32 + 4 + 4 + 264 + 4 + 20 + 16];
	RC4 k;
	int len, o;

	if (!s || !s->lic) {
		rdp_fail(r, "The server sent a license challenge too early.");
		return;
	}
	if (n < 8 + 16 || (len = get16(p + 6)) > n - 8 - 16 || len > 256) {
		rdp_fail(r, "The server sent a bad license challenge.");
		return;
	}
	/* PLATFORM_CHALLENGE_RESPONSE_DATA, then the CLIENT_HARDWARE_ID */
	put16(d, 0x0100);		/* wVersion */
	put16(d + 2, 0xFF00);		/* OTHER_PLATFORM_CHALLENGE_TYPE */
	put16(d + 4, 3);		/* LICENSE_DETAIL_DETAIL */
	put16(d + 6, len);
	rc4_init(&k, s->lkey, 16);
	rc4(&k, p + 8, d + 8, len);
	mac(s->lmac, 16, d + 8, len, m);
	if (memcmp(m, p + 8 + len, 16) != 0) {
		rdp_fail(r, "The license challenge does not match ntrdpc's "
			 "keys.");
		return;
	}
	put32(d + 8 + len, PLATFORM_ID);
	md_sum(MD_MD5, (const u8 *)r->opt.client, (int)strlen(r->opt.client),
	       d + 8 + len + 4);
	mac(s->lmac, 16, d, 8 + len + 20, m);

	o = 32 + 4;
	put16(b + o, 0x0009);		/* BB_ENCRYPTED_DATA_BLOB */
	put16(b + o + 2, 8 + len);
	rc4_init(&k, s->lkey, 16);
	rc4(&k, d, b + o + 4, 8 + len);
	o += 4 + 8 + len;
	put16(b + o, 0x0009);
	put16(b + o + 2, 20);
	rc4_init(&k, s->lkey, 16);
	rc4(&k, d + 8 + len, b + o + 4, 20);
	o += 4 + 20;
	memcpy(b + o, m, 16);
	o += 16;
	send_license(r, b, o - 32, 0x15);
}

/* a licensing PDU, from its preamble on */
void
sec_license(RDP *r, const u8 *p, int n)
{
	u32 code, next;
	char msg[80];

	if (n < 4)
		return;
	switch (p[0]) {
	case 0x01:			/* LICENSE_REQUEST */
		license_request(r, p + 4, n - 4);
		return;
	case 0x02:			/* PLATFORM_CHALLENGE */
		platform_challenge(r, p + 4, n - 4);
		return;
	case 0x03:			/* NEW_LICENSE */
	case 0x04:			/* UPGRADE_LICENSE */
		break;
	case 0xFF:			/* ERROR_ALERT */
		code = n >= 12 ? get32(p + 4) : 0;
		next = n >= 12 ? get32(p + 8) : 0;
		/* STATUS_VALID_CLIENT, or the server lets us in anyway
		   (ST_NO_TRANSITION) */
		if (code == 7 || next == 2)
			break;
		sprintf(msg, "The server refused the license (error %lu).",
			(unsigned long)code);
		rdp_fail(r, msg);
		return;
	default:
		return;
	}
	if (r->state == RS_LICENSE) {
		r->state = RS_DEMAND;
		ui_state(r);
	}
}
