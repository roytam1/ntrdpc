/*
 * crypt.c - the small hashes and RC4 of NLA (nla.c) and of Standard RDP
 * Security (sec.c): MD4 (RFC 1320), MD5 (RFC 1321), SHA-1 (FIPS 180-1),
 * HMAC-MD5 (RFC 2104) and RC4.  The byte count is two 32-bit halves: the
 * NT 3.1 compilers have no 64-bit integer.  test/nlatest checks them.
 */

#include <string.h>
#include "ntrdpc.h"

#define ROL(x, n)	(((x) << (n)) | ((x) >> (32 - (n))))

static u32
get32(const u8 *p)
{
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static u32
get32be(const u8 *p)
{
	return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3];
}

static void
put32(u8 *p, u32 v)
{
	p[0] = (u8)v;
	p[1] = (u8)(v >> 8);
	p[2] = (u8)(v >> 16);
	p[3] = (u8)(v >> 24);
}

static void
put32be(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

static void
md4_block(u32 *h, const u8 *p)
{
	static const u8 k2[16] = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14,
				   3, 7, 11, 15 };
	static const u8 k3[16] = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13,
				   3, 11, 7, 15 };
	static const u8 s1[4] = { 3, 7, 11, 19 }, s2[4] = { 3, 5, 9, 13 },
		s3[4] = { 3, 9, 11, 15 };
	u32 x[16], a = h[0], b = h[1], c = h[2], d = h[3], t;
	int i;

	for (i = 0; i < 16; i++)
		x[i] = get32(p + 4 * i);
	for (i = 0; i < 16; i++) {
		t = a + ((b & c) | (~b & d)) + x[i];
		t = ROL(t, s1[i & 3]);
		a = d; d = c; c = b; b = t;
	}
	for (i = 0; i < 16; i++) {
		t = a + ((b & c) | (b & d) | (c & d)) + x[k2[i]] +
			0x5A827999UL;
		t = ROL(t, s2[i & 3]);
		a = d; d = c; c = b; b = t;
	}
	for (i = 0; i < 16; i++) {
		t = a + (b ^ c ^ d) + x[k3[i]] + 0x6ED9EBA1UL;
		t = ROL(t, s3[i & 3]);
		a = d; d = c; c = b; b = t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
}

static void
md5_block(u32 *h, const u8 *p)
{
	static const u32 k[64] = {
		0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL,
		0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
		0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL,
		0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
		0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL,
		0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
		0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL,
		0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
		0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL,
		0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
		0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL,
		0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
		0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL,
		0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
		0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
		0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL
	};
	static const u8 s[16] = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23,
				  6, 10, 15, 21 };
	u32 x[16], a = h[0], b = h[1], c = h[2], d = h[3], f, t;
	int i, g;

	for (i = 0; i < 16; i++)
		x[i] = get32(p + 4 * i);
	for (i = 0; i < 64; i++) {
		switch (i >> 4) {
		case 0:
			f = (b & c) | (~b & d);
			g = i;
			break;
		case 1:
			f = (d & b) | (~d & c);
			g = (5 * i + 1) & 15;
			break;
		case 2:
			f = b ^ c ^ d;
			g = (3 * i + 5) & 15;
			break;
		default:
			f = c ^ (b | ~d);
			g = (7 * i) & 15;
			break;
		}
		t = a + f + k[i] + x[g];
		t = ROL(t, s[(i >> 4) * 4 + (i & 3)]);
		a = d;
		d = c;
		c = b;
		b = b + t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
}

static void
sha1_block(u32 *h, const u8 *p)
{
	u32 w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], t;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = get32be(p + 4 * i);
	for (; i < 80; i++) {
		t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
		w[i] = ROL(t, 1);
	}
	for (i = 0; i < 80; i++) {
		if (i < 20)
			t = ((b & c) | (~b & d)) + 0x5A827999UL;
		else if (i < 40)
			t = (b ^ c ^ d) + 0x6ED9EBA1UL;
		else if (i < 60)
			t = ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDCUL;
		else
			t = (b ^ c ^ d) + 0xCA62C1D6UL;
		t += ROL(a, 5) + e + w[i];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

void
md_init(MD *m, int kind)
{
	m->h[0] = 0x67452301UL;
	m->h[1] = 0xefcdab89UL;
	m->h[2] = 0x98badcfeUL;
	m->h[3] = 0x10325476UL;
	m->h[4] = 0xc3d2e1f0UL;
	m->lo = m->hi = 0;
	m->kind = kind;
}

void
md_update(MD *m, const u8 *p, int n)
{
	int used = (int)(m->lo & 63), k;

	while (n > 0) {
		k = 64 - used < n ? 64 - used : n;
		memcpy(m->buf + used, p, (size_t)k);
		if ((m->lo += (u32)k) < (u32)k)
			m->hi++;
		used += k;
		p += k;
		n -= k;
		if (used == 64) {
			if (m->kind == MD_SHA1)
				sha1_block(m->h, m->buf);
			else if (m->kind == MD_MD4)
				md4_block(m->h, m->buf);
			else
				md5_block(m->h, m->buf);
			used = 0;
		}
	}
}

/* out: 16 bytes (MD4, MD5) or 20 (SHA-1) */
void
md_final(MD *m, u8 *out)
{
	static const u8 pad[64] = { 0x80 };
	u32 lo = m->lo << 3, hi = m->hi << 3 | m->lo >> 29;
	u8 len[8];
	int i;

	if (m->kind == MD_SHA1) {
		put32be(len, hi);
		put32be(len + 4, lo);
	} else {
		put32(len, lo);
		put32(len + 4, hi);
	}
	md_update(m, pad, (int)((55 - (m->lo & 63)) & 63) + 1);
	md_update(m, len, 8);
	if (m->kind == MD_SHA1)
		for (i = 0; i < 5; i++)
			put32be(out + 4 * i, m->h[i]);
	else
		for (i = 0; i < 4; i++)
			put32(out + 4 * i, m->h[i]);
	memset(m, 0, sizeof(MD));
}

void
md_sum(int kind, const u8 *p, int n, u8 *out)
{
	MD m;

	md_init(&m, kind);
	md_update(&m, p, n);
	md_final(&m, out);
}

/* HMAC-MD5 with a 16-byte key, in parts */
void
hmac_init(HMAC *h, const u8 *key)
{
	u8 b[64];
	int i;

	memcpy(h->key, key, 16);
	memset(b, 0x36, 64);
	for (i = 0; i < 16; i++)
		b[i] ^= key[i];
	md_init(&h->in, MD_MD5);
	md_update(&h->in, b, 64);
}

void
hmac_final(HMAC *h, u8 *out)
{
	u8 b[64], inner[16];
	MD m;
	int i;

	md_final(&h->in, inner);
	memset(b, 0x5C, 64);
	for (i = 0; i < 16; i++)
		b[i] ^= h->key[i];
	md_init(&m, MD_MD5);
	md_update(&m, b, 64);
	md_update(&m, inner, 16);
	md_final(&m, out);
	memset(h, 0, sizeof(HMAC));
}

void
hmac_md5(const u8 *key, const u8 *p, int n, u8 *out)
{
	HMAC h;

	hmac_init(&h, key);
	md_update(&h.in, p, n);
	hmac_final(&h, out);
}

void
rc4_init(RC4 *k, const u8 *key, int len)
{
	int i, j = 0;
	u8 t;

	for (i = 0; i < 256; i++)
		k->s[i] = (u8)i;
	for (i = 0; i < 256; i++) {
		j = (j + k->s[i] + key[i % len]) & 255;
		t = k->s[i];
		k->s[i] = k->s[j];
		k->s[j] = t;
	}
	k->i = k->j = 0;
}

void
rc4(RC4 *k, const u8 *in, u8 *out, int n)
{
	int i = k->i, j = k->j;
	u8 t;

	while (n-- > 0) {
		i = (i + 1) & 255;
		j = (j + k->s[i]) & 255;
		t = k->s[i];
		k->s[i] = k->s[j];
		k->s[j] = t;
		*out++ = (u8)(*in++ ^ k->s[(k->s[i] + k->s[j]) & 255]);
	}
	k->i = i;
	k->j = j;
}
