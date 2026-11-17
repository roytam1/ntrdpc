/*
 * nlatest.c - checks the crypto of nla.c with published examples:
 * MD4 (RFC 1320), MD5 (RFC 1321), HMAC-MD5 (RFC 2202), RC4, NTLMv2 and
 * sealing (MS-NLMP 4.2.4), and a CredSSP TSRequest that parses back.
 * It includes nla.c to reach its static functions; crypt.c is linked.
 * Exit 0 = all right.
 */

#include "../nla.c"

/* what nla.c calls outside; unused here */
void rdp_out(RDP *r, const u8 *d, int n) { (void)r; (void)d; (void)n; }
void rdp_fail(RDP *r, const char *m) { (void)r; printf("fail: %s\n", m); }
void rdp_random(RDP *r, u8 *o, int n) { (void)r; memset(o, 0x55, (size_t)n); }
int tls_server_key(RDP *r, const u8 **k, int *n)
{ (void)r; (void)k; (void)n; return 0; }
void rdp_nla_done(RDP *r) { (void)r; }
void ui_state(RDP *r) { (void)r; }

static int fails, checks;

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
	u8 want[256];
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
md5(const u8 *p, int n, u8 *out)
{
	MD m;

	md_init(&m, MD_MD5);
	md_update(&m, p, n);
	md_final(&m, out);
}

int
main(void)
{
	static const char digits[] = "1234567890123456789012345678901234567890"
		"1234567890123456789012345678901234567890";
	u8 out[64], key[16], buf[256], v2[16], nthash[16], proof[16], sbk[16];
	u8 temp[128], w[64];
	int n, t;
	MD m;
	HMAC h;
	RC4 k;
	NLA a;
	TSREQ ts;

	/* MD4, RFC 1320 */
	md_sum(MD_MD4, (const u8 *)"", 0, out);
	check("md4 empty", out, 16, "31d6cfe0d16ae931b73c59d7e0c089c0");
	md_sum(MD_MD4, (const u8 *)"abc", 3, out);
	check("md4 abc", out, 16, "a448017aaf21d8525fc10ae87aa6729d");
	md_sum(MD_MD4, (const u8 *)"message digest", 14, out);
	check("md4 message digest", out, 16, "d9130a8164549fe818874806e1c7014b");
	md_sum(MD_MD4, (const u8 *)digits, 80, out);
	check("md4 80 digits", out, 16, "e33b4ddc9c38f2199c3e7b164fcc0536");

	/* MD5, RFC 1321; one million a, in odd pieces */
	md5((const u8 *)"", 0, out);
	check("md5 empty", out, 16, "d41d8cd98f00b204e9800998ecf8427e");
	md5((const u8 *)"abc", 3, out);
	check("md5 abc", out, 16, "900150983cd24fb0d6963f7d28e17f72");
	md5((const u8 *)digits, 80, out);
	check("md5 80 digits", out, 16, "57edf4a22be3c955ac49da2e2107b67a");
	memset(buf, 'a', sizeof(buf));
	md_init(&m, MD_MD5);
	for (n = 0; n < 1000000; n += t) {
		t = 1000000 - n < 77 ? 1000000 - n : 77;
		md_update(&m, buf, t);
	}
	md_final(&m, out);
	check("md5 million a", out, 16, "7707d6ae4e027c70eea2a935c2296f21");

	/* HMAC-MD5, RFC 2202 tests 1 and 3 */
	memset(key, 0x0B, 16);
	hmac_md5(key, (const u8 *)"Hi There", 8, out);
	check("hmac-md5 1", out, 16, "9294727a3638bb1c13f48ef8158bfc9d");
	memset(key, 0xAA, 16);
	memset(buf, 0xDD, 50);
	hmac_md5(key, buf, 50, out);
	check("hmac-md5 3", out, 16, "56be34521d144c88dbb8c733f0e8b3f6");

	/* RC4 */
	rc4_init(&k, (const u8 *)"Key", 3);
	rc4(&k, (const u8 *)"Plaintext", out, 9);
	check("rc4 Key", out, 9, "bbf316e8d940af0ad3");
	rc4_init(&k, (const u8 *)"Secret", 6);
	rc4(&k, (const u8 *)"Attack at", out, 9);	/* in two parts */
	rc4(&k, (const u8 *)" dawn", out + 9, 5);
	check("rc4 Secret", out, 14, "45a01f645fc35b383552544b9bf5");

	/* NTLMv2, MS-NLMP 4.2.4: User, Domain, Password */
	n = wide(w, "Password", 64, 0);
	md_sum(MD_MD4, w, n, nthash);
	hmac_init(&h, nthash);
	n = wide(w, "User", 64, 1);
	md_update(&h.in, w, n);
	n = wide(w, "Domain", 64, 0);
	md_update(&h.in, w, n);
	hmac_final(&h, v2);
	check("NTOWFv2", v2, 16, "0c868a403bfd7a93a3001ef22ef02e3f");
	n = unhex("0101000000000000" "0000000000000000" "aaaaaaaaaaaaaaaa"
		  "00000000"
		  "02000c0044006f006d00610069006e00"
		  "01000c00530065007200760065007200"
		  "00000000" "00000000", temp);
	hmac_init(&h, v2);
	unhex("0123456789abcdef", buf);
	md_update(&h.in, buf, 8);
	md_update(&h.in, temp, n);
	hmac_final(&h, proof);
	check("NTProofStr", proof, 16, "68cd0ab851e51c96aabc927bebef6a1c");
	hmac_md5(v2, proof, 16, sbk);
	check("SessionBaseKey", sbk, 16, "8de40ccadbc14a82f15cb0ad0de95ca3");
	memset(key, 0x55, 16);			/* RandomSessionKey */
	rc4_init(&k, sbk, 16);
	rc4(&k, key, out, 16);
	check("EncryptedRandomSessionKey", out, 16,
	      "c5dad2544fc9799094ce1ce90bc9d03e");

	/* sealing, MS-NLMP 4.2.4.4: "Plaintext" as UTF-16, sequence 0 */
	memset(&a, 0, sizeof(a));
	a.flags = NF_OURS;
	derive(key, "session key to client-to-server signing key magic "
	       "constant", a.sign_c);
	check("client signing key", a.sign_c, 16,
	      "4788dc861b4782f35d43fd98fe1a2d39");
	derive(key, "session key to client-to-server sealing key magic "
	       "constant", out);
	check("client sealing key", out, 16,
	      "59f600973cc4960a25480a7c196e4c58");
	rc4_init(&a.seal_c, out, 16);
	n = wide(w, "Plaintext", 64, 0);
	seal(&a, w, n, buf);
	check("sealed data", buf + 16, n, "54e50165bf1936dc996020c1811b0f06fb5f");
	check("signature", buf, 16, "010000007fb38ec5c55d497600000000");

	/* a TSRequest that parses back */
	memset(out, 0x11, 32);
	n = ts_request(buf, temp, 100, NULL, 0, temp, 40, out);
	if (!ts_parse(buf, n, &ts) || ts.version != CSSP_VERSION ||
	    ts.toklen != 100 || memcmp(ts.tok, temp, 100) ||
	    ts.pkalen != 40 || memcmp(ts.pka, temp, 40)) {
		printf("FAIL TSRequest round trip\n");
		fails++;
	}
	checks++;

	printf("nlatest: %d of %d right\n", checks - fails, checks);
	return fails != 0;
}
