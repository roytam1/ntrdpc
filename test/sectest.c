/*
 * sectest.c - checks sec.c (Standard RDP Security and licensing) and the
 * SHA-1 of crypt.c: SHA-1 with the FIPS 180 examples; the certificate
 * forms, RSA, the RC4 and MAC keys of all three key sizes, the key update
 * and the licensing messages with the values of secvals.h, which an
 * independent model made (python3 secmodel.py sectest.der > secvals.h).
 * It includes tls.c and sec.c to reach their static functions; crypt.c and
 * BearSSL are linked.  Exit 0 = all right.
 */

#define rdp_random tls_rdp_random	/* the test gives its own random */
#include "../tls.c"
#undef rdp_random
void rdp_random(RDP *r, u8 *out, int len);
#include "../sec.c"
#include "secvals.h"

static int fails, checks;
static int failed;			/* rdp_fail was called */
static u8 sent[2048];			/* the last rdp_send_sec */
static int sentlen, sentflags;
static const u8 *rnd;			/* what rdp_random gives next */

/* what tls.c and sec.c call outside */
int rdp_keep(RDP *r, const u8 *d, int n) { (void)r; (void)d; (void)n; return 1; }
void rdp_tls_up(RDP *r) { (void)r; }
const char *rdp_error_text(RDP *r) { (void)r; return ""; }
void rdp_fail(RDP *r, const char *m) { (void)r; failed = 1; printf("(fail: %s)\n", m); }
void ui_send(RDP *r, const u8 *d, int n) { (void)r; (void)d; (void)n; }
void ui_random(RDP *r, u8 *b, int n) { (void)r; memset(b, 0, (size_t)n); }
void ui_state(RDP *r) { (void)r; }

void
rdp_random(RDP *r, u8 *out, int len)
{
	(void)r;
	memcpy(out, rnd, (size_t)len);
	rnd += len;
}

void
rdp_send_sec(RDP *r, u8 *d, int n, int flags)
{
	(void)r;
	sentlen = n < (int)sizeof(sent) ? n : (int)sizeof(sent);
	memcpy(sent, d, (size_t)sentlen);
	sentflags = flags;
}

static int
unhex(const char *h, u8 *out)
{
	int n = 0, v;

	while (h[0] && h[1]) {
		sscanf(h, "%2x", &v);
		out[n++] = (u8)v;
		h += 2;
	}
	return n;
}

static void
check(const char *name, const u8 *got, int len, const char *hex)
{
	static u8 want[2048];
	int n = unhex(hex, want), i;

	checks++;
	if (n == len && memcmp(got, want, (size_t)n) == 0)
		return;
	fails++;
	printf("FAIL %s:\n  got  ", name);
	for (i = 0; i < len; i++)
		printf("%02x", got[i]);
	printf("\n  want %s\n", hex);
}

static void
truth(const char *name, int ok)
{
	checks++;
	if (!ok) {
		fails++;
		printf("FAIL %s\n", name);
	}
}

static void
sha1(const char *s, int n, u8 *out)
{
	md_sum(MD_SHA1, (const u8 *)s, n, out);
}

/* a licensing PDU: the preamble, then the message */
static void
license_pdu(RDP *r, int type, const char *hex)
{
	static u8 b[2048];
	int n = unhex(hex, b + 4);

	b[0] = (u8)type;
	b[1] = 3;
	put16(b + 2, n + 4);
	sentlen = 0;
	sec_license(r, b, n + 4);
}

static void
keys(int method, const char *mk, const char *ek, const char *dk,
     const char *sig, const char *cipher, const char *upd)
{
	static const char data[] = "ntrdpc test data";
	RDP r;
	SEC *s = (SEC *)calloc(1, sizeof(SEC));
	u8 cr[32], d[16], m[8], plain[16];
	RC4 k;
	int i;

	for (i = 0; i < 32; i++) {
		cr[i] = (u8)i;
		s->srand[i] = (u8)(0x80 + i);
	}
	s->method = method;
	s->keylen = method == 2 ? 16 : 8;
	make_keys(s, cr);
	s->on = 1;
	check("mac key", s->mackey, s->keylen, mk);
	check("encrypt key", s->enc0, s->keylen, ek);
	check("decrypt key", s->dec0, s->keylen, dk);
	memset(&r, 0, sizeof(r));
	r.sec = s;
	memcpy(d, data, 16);
	sec_encrypt(&r, d, 16, m);
	check("mac", m, 8, sig);
	check("encrypted", d, 16, cipher);
	rc4_init(&k, s->dec0, s->keylen);	/* as the server encrypts */
	rc4(&k, (const u8 *)data, plain, 16);
	sec_decrypt(&r, plain, 16);
	truth("decrypted", memcmp(plain, data, 16) == 0);
	update_key(s, s->enc0, s->enc, &s->encrc4);
	check("key update", s->enc, s->keylen, upd);
	sec_free(s);
}

int
main(void)
{
	static u8 buf[4096], chain[2048];
	static const char abc56[] = "abcdbcdecdefdefgefghfghighijhijkijkljklm"
		"klmnlmnomnopnopq";
	u8 out[600], cr[32], rr[32 + 48];
	RSAKEY key;
	RDP r;
	MD m;
	int n, t, i, clen;

	/* SHA-1, FIPS 180-1 and RFC 3174 */
	sha1("", 0, out);
	check("sha1 empty", out, 20, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	sha1("abc", 3, out);
	check("sha1 abc", out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
	sha1(abc56, 56, out);
	check("sha1 56", out, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	memset(buf, 'a', 1000);
	md_init(&m, MD_SHA1);
	for (n = 0; n < 1000000; n += t) {
		t = 1000000 - n < 77 ? 1000000 - n : 77;
		md_update(&m, buf, t);
	}
	md_final(&m, out);
	check("sha1 million a", out, 20,
	      "34aa973cd4c4daa4f61eeb2bdbad27316534016f");

	/* the certificate forms, and RSA with their key */
	for (i = 0; i < 32; i++)
		cr[i] = (u8)i;
	memset(&key, 0, sizeof(key));
	n = unhex(T_PROP, buf);
	truth("proprietary certificate", read_cert(buf, n, &key));
	check("proprietary modulus", key.n, key.nlen, T_N);
	check("proprietary exponent", key.e, key.elen, "00010001");
	n = rsa_le(&key, cr, 32, out);
	check("rsa", out, n, T_RSA);
	clen = unhex(T_CERT, buf);
	put32(chain, 0x80000002UL);	/* X.509, temporary */
	put32(chain + 4, 2);
	put32(chain + 8, (u32)clen);
	memcpy(chain + 12, buf, (size_t)clen);
	put32(chain + 12 + clen, (u32)clen);
	memcpy(chain + 16 + clen, buf, (size_t)clen);
	memset(&key, 0, sizeof(key));
	truth("x509 chain", read_cert(chain, 16 + 2 * clen, &key));
	check("x509 modulus", key.n, key.nlen, T_N);
	check("x509 exponent", key.e, key.elen, "010001");
	n = rsa_le(&key, cr, 32, out);
	check("rsa x509", out, n, T_RSA);
	chain[0] = 3;
	truth("unknown certificate", !read_cert(chain, 16 + 2 * clen, &key));

	/* the session keys, the MAC, RC4 and the key update */
	keys(1, T_M1_MAC, T_M1_ENC, T_M1_DEC, T_M1_SIG, T_M1_CIPHER, T_M1_UPD);
	keys(8, T_M8_MAC, T_M8_ENC, T_M8_DEC, T_M8_SIG, T_M8_CIPHER, T_M8_UPD);
	keys(2, T_M2_MAC, T_M2_ENC, T_M2_DEC, T_M2_SIG, T_M2_CIPHER, T_M2_UPD);

	/* licensing as under TLS: no SEC before, the key from the request */
	memset(&r, 0, sizeof(r));
	strcpy(r.opt.user, "tenox");
	strcpy(r.opt.client, "HEADLESS");
	r.state = RS_LICENSE;
	for (i = 0; i < 32; i++)
		rr[i] = (u8)(0x20 + i);
	for (i = 0; i < 48; i++)
		rr[32 + i] = (u8)(0x40 + i);
	rnd = rr;
	license_pdu(&r, 0x01, T_LREQ);
	truth("license request: no failure", !failed);
	truth("license request: a licensing PDU",
	      sentflags == SEC_LICENSE_PKT);
	check("new license request", sent, sentlen, T_NLR);
	truth("licensing keys", r.sec && r.sec->lic);
	if (r.sec) {
		check("licensing mac key", r.sec->lmac, 16, T_LMAC);
		check("licensing key", r.sec->lkey, 16, T_LKEY);
	}
	license_pdu(&r, 0x02, T_CHAL);
	truth("challenge: no failure", !failed);
	check("challenge response", sent, sentlen, T_RESP);
	truth("still licensing", r.state == RS_LICENSE);
	license_pdu(&r, 0x03, "00");
	truth("new license: demand next", r.state == RS_DEMAND);
	r.state = RS_LICENSE;
	license_pdu(&r, 0xFF, "0700000002000000" "04000000");
	truth("valid client", r.state == RS_DEMAND && !failed);
	r.state = RS_LICENSE;
	license_pdu(&r, 0xFF, "0600000001000000" "04000000");
	truth("no license server: fails", failed);
	sec_free(r.sec);

	printf("sectest: %d of %d right\n", checks - fails, checks);
	return fails != 0;
}
