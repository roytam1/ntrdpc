/*
 * tls.c - TLS 1.2 under the RDP core, with BearSSL (bearssl/): the client
 * side of RDP's Enhanced Security (MS-RDPBCGR 5.4).  rdp.c gives it the
 * bytes from the socket (tls_input) and the bytes to send (tls_send).  The
 * plain text goes back to rdp.c (rdp_keep), the TLS records to ui_send.
 *
 * Suites: ECDHE_RSA, ECDHE_ECDSA and RSA, each with AES-128-GCM and
 * SHA-256; the curve is P-256.  Windows has an RSA certificate, ntrdps an
 * ECDSA one.  The certificate is read for its key only, not checked: there
 * is no list of trusted authorities, and the RDP certificate of Windows is
 * self-signed anyway.  NLA (nla.c) binds the logon to this key.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ntrdpc.h"
#include "bearssl.h"

/* the server's certificate: decoded for its key, kept whole for nla.c */
typedef struct {
	const br_x509_class *vtable;
	br_x509_decoder_context dec;
	int depth;
	u8 *cert;
	long len, cap;
} XCERT;

struct TLS {
	br_ssl_client_context sc;
	XCERT xc;
	u8 *io;				/* BearSSL's record buffers */
	int up;				/* the handshake is done */
};

static br_hmac_drbg_context rng;
static int seeded;

/* random bytes: the front end's entropy, through HMAC-DRBG (SHA-256) */
void
rdp_random(RDP *r, u8 *out, int len)
{
	u8 e[64];

	ui_random(r, e, sizeof(e));
	if (!seeded) {
		br_hmac_drbg_init(&rng, &br_sha256_vtable, e, sizeof(e));
		seeded = 1;
	} else {
		br_hmac_drbg_update(&rng, e, sizeof(e));
	}
	br_hmac_drbg_generate(&rng, out, (size_t)len);
	memset(e, 0, sizeof(e));
}


/*
 * The certificate "check": keep the first certificate (the server's own),
 * decode its key, accept it.
 */

static void
xc_start_chain(const br_x509_class **ctx, const char *server_name)
{
	XCERT *x = (XCERT *)ctx;

	(void)server_name;
	x->depth = 0;
	x->len = 0;
}

static void
xc_start_cert(const br_x509_class **ctx, uint32_t length)
{
	XCERT *x = (XCERT *)ctx;

	if (x->depth != 0)
		return;
	br_x509_decoder_init(&x->dec, 0, 0);
	if (length > (uint32_t)x->cap && length < 65536L) {
		if (x->cert)
			free(x->cert);
		x->cert = (u8 *)malloc((size_t)length);
		x->cap = x->cert ? (long)length : 0;
	}
}

static void
xc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	XCERT *x = (XCERT *)ctx;

	if (x->depth != 0)
		return;
	br_x509_decoder_push(&x->dec, buf, len);
	if (x->cert && x->len + (long)len <= x->cap) {
		memcpy(x->cert + x->len, buf, len);
		x->len += (long)len;
	}
}

static void
xc_end_cert(const br_x509_class **ctx)
{
	((XCERT *)ctx)->depth++;
}

static unsigned
xc_end_chain(const br_x509_class **ctx)
{
	XCERT *x = (XCERT *)ctx;
	int err;

	if (x->depth == 0)
		return BR_ERR_X509_EMPTY_CHAIN;
	err = br_x509_decoder_last_error(&x->dec);
	if (err)
		return (unsigned)err;
	if (!br_x509_decoder_get_pkey(&x->dec))
		return BR_ERR_X509_UNSUPPORTED;
	return 0;
}

static const br_x509_pkey *
xc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	XCERT *x = (XCERT *)ctx;

	if (usages)
		*usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
	return br_x509_decoder_get_pkey(&x->dec);
}

static const br_x509_class xc_class = {
	sizeof(XCERT),
	xc_start_chain,
	xc_start_cert,
	xc_append,
	xc_end_cert,
	xc_end_chain,
	xc_get_pkey
};


/*
 * The engine.
 */

static void
tls_closed(RDP *r)
{
	br_ssl_engine_context *e = &r->tls->sc.eng;
	int err = br_ssl_engine_last_error(e);
	char msg[80];

	if (err == BR_ERR_OK || err == BR_ERR_IO) {
		rdp_fail(r, rdp_error_text(r));
		return;
	}
	if (!r->tls->up && (err == BR_ERR_UNSUPPORTED_VERSION ||
	    err == BR_ERR_RECV_FATAL_ALERT + 40 ||
	    err == BR_ERR_RECV_FATAL_ALERT + 70)) {
		/* an older TLS (Windows 7, Vista, 2008, 2003): try again with
		   plain RDP and RDP security (sec.c) */
		r->again = 1;
		rdp_fail(r, "The server has only an older TLS. ntrdpc needs "
			 "TLS 1.2.");
		return;
	}
	if (err >= BR_ERR_RECV_FATAL_ALERT)
		sprintf(msg, "The server ended TLS (alert %d).",
			err - BR_ERR_RECV_FATAL_ALERT);
	else
		sprintf(msg, "TLS failed (BearSSL error %d).", err);
	rdp_fail(r, msg);
}

/* records to the socket */
static void
drain(RDP *r)
{
	br_ssl_engine_context *e = &r->tls->sc.eng;
	unsigned char *b;
	size_t len;

	while (r->state != RS_DONE &&
	       (br_ssl_engine_current_state(e) & BR_SSL_SENDREC)) {
		b = br_ssl_engine_sendrec_buf(e, &len);
		ui_send(r, b, (int)len);
		br_ssl_engine_sendrec_ack(e, len);
	}
}

/* sends what waits, keeps the plain text, notices the end of the
   handshake; 0 when the session is over */
static int
pump(RDP *r)
{
	TLS *t = r->tls;
	br_ssl_engine_context *e = &t->sc.eng;
	unsigned st;
	unsigned char *b;
	size_t len;

	for (;;) {
		drain(r);
		if (r->state == RS_DONE)
			return 0;
		st = br_ssl_engine_current_state(e);
		if (st & BR_SSL_CLOSED) {
			tls_closed(r);
			return 0;
		}
		if (!(st & BR_SSL_RECVAPP))
			break;
		b = br_ssl_engine_recvapp_buf(e, &len);
		if (!rdp_keep(r, b, (int)len))
			return 0;
		br_ssl_engine_recvapp_ack(e, len);
	}
	if (!t->up && (st & BR_SSL_SENDAPP)) {
		t->up = 1;
		rdp_tls_up(r);
	}
	return r->state != RS_DONE;
}

/* starts the handshake: the ClientHello goes out */
int
tls_start(RDP *r)
{
	static const uint16_t suites[] = {
		BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_RSA_WITH_AES_128_GCM_SHA256
	};
	TLS *t;
	br_ssl_engine_context *e;
	u8 seed[32];

	t = (TLS *)calloc(1, sizeof(TLS));
	if (!t || !(t->io = (u8 *)malloc(BR_SSL_BUFSIZE_BIDI))) {
		if (t)
			free(t);
		rdp_fail(r, "Out of memory.");
		return 0;
	}
	r->tls = t;
	br_ssl_client_zero(&t->sc);
	e = &t->sc.eng;
	br_ssl_engine_set_versions(e, BR_TLS12, BR_TLS12);
	br_ssl_engine_set_suites(e, suites, sizeof(suites) / sizeof(suites[0]));
	br_ssl_engine_set_hash(e, br_sha256_ID, &br_sha256_vtable);
	br_ssl_engine_set_prf_sha256(e, &br_tls12_sha256_prf);
	br_ssl_engine_set_aes_ctr(e, &br_aes_ct_ctr_vtable);
	br_ssl_engine_set_ghash(e, &br_ghash_ctmul32);
	br_ssl_engine_set_gcm(e, &br_sslrec_in_gcm_vtable,
			      &br_sslrec_out_gcm_vtable);
	br_ssl_engine_set_ec(e, &br_ec_p256_m15);
	br_ssl_engine_set_rsavrfy(e, &br_rsa_i15_pkcs1_vrfy);
	br_ssl_engine_set_ecdsa(e, &br_ecdsa_i15_vrfy_asn1);
	br_ssl_client_set_rsapub(&t->sc, &br_rsa_i15_public);
	t->xc.vtable = &xc_class;
	br_ssl_engine_set_x509(e, &t->xc.vtable);
	br_ssl_engine_set_buffer(e, t->io, BR_SSL_BUFSIZE_BIDI, 1);
	rdp_random(r, seed, sizeof(seed));
	br_ssl_engine_inject_entropy(e, seed, sizeof(seed));
	memset(seed, 0, sizeof(seed));
	if (!br_ssl_client_reset(&t->sc, NULL, 0)) {
		tls_closed(r);
		return 0;
	}
	return pump(r);
}

void
tls_free(TLS *t)
{
	if (!t)
		return;
	if (t->xc.cert)
		free(t->xc.cert);
	if (t->io)
		free(t->io);
	memset(t, 0, sizeof(TLS));
	free(t);
}

/* bytes from the socket; 0 when the session is over */
int
tls_input(RDP *r, const u8 *d, int n)
{
	br_ssl_engine_context *e = &r->tls->sc.eng;
	unsigned char *b;
	size_t len;

	for (;;) {
		if (!pump(r))
			return 0;
		if (n <= 0)
			return 1;
		if (!(br_ssl_engine_current_state(e) & BR_SSL_RECVREC)) {
			rdp_fail(r, "TLS stalled.");
			return 0;
		}
		b = br_ssl_engine_recvrec_buf(e, &len);
		if (len > (size_t)n)
			len = (size_t)n;
		memcpy(b, d, len);
		br_ssl_engine_recvrec_ack(e, len);
		d += len;
		n -= (int)len;
	}
}

/* plain text to the server */
void
tls_send(RDP *r, const u8 *d, int n)
{
	br_ssl_engine_context *e = &r->tls->sc.eng;
	unsigned char *b;
	size_t len;

	while (n > 0 && r->state != RS_DONE) {
		drain(r);
		if (!(br_ssl_engine_current_state(e) & BR_SSL_SENDAPP)) {
			if (br_ssl_engine_current_state(e) & BR_SSL_CLOSED)
				tls_closed(r);
			else
				rdp_fail(r, "TLS cannot send.");
			return;
		}
		b = br_ssl_engine_sendapp_buf(e, &len);
		if (len > (size_t)n)
			len = (size_t)n;
		memcpy(b, d, len);
		br_ssl_engine_sendapp_ack(e, len);
		d += len;
		n -= (int)len;
	}
	br_ssl_engine_flush(e, 0);
	drain(r);
}


/*
 * The server's public key as NLA wants it: the bits of subjectPublicKey in
 * the certificate (for RSA the DER RSAPublicKey), without the count of
 * unused bits.
 */

/* a DER element at *p: checks the tag, moves *p to the contents and
   returns their length, or -1 */
long
der_read(const u8 **p, const u8 *end, int tag)
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

/* skips one element of any tag */
static int
der_skip(const u8 **p, const u8 *end)
{
	long n;

	if (end - *p < 2)
		return 0;
	n = der_read(p, end, **p);
	if (n < 0)
		return 0;
	*p += n;
	return 1;
}

/* the subjectPublicKey bits of a DER certificate (sec.c reads RDP's
   X.509 certificates with it too) */
int
cert_key(const u8 *cert, int clen, const u8 **key, int *len)
{
	const u8 *p = cert, *end = cert + clen;
	long n;
	int i;

	if (!p || der_read(&p, end, 0x30) < 0 || der_read(&p, end, 0x30) < 0)
		return 0;
	if (p < end && *p == 0xA0 && !der_skip(&p, end))	/* version */
		return 0;
	for (i = 0; i < 5; i++)		/* serial, signature, issuer,
					   validity, subject */
		if (!der_skip(&p, end))
			return 0;
	if (der_read(&p, end, 0x30) < 0 || !der_skip(&p, end))
		return 0;
	n = der_read(&p, end, 0x03);
	if (n < 2 || *p != 0)
		return 0;
	*key = p + 1;
	*len = (int)(n - 1);
	return 1;
}

int
tls_server_key(RDP *r, const u8 **key, int *len)
{
	XCERT *x = &r->tls->xc;

	return cert_key(x->cert, (int)x->len, key, len);
}
