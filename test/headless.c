/*
 * headless.c - a test front end for the ntrdpc core on Unix.  It connects,
 * runs the session for some seconds, can send input, then ends the session
 * and writes the screen as a 24-bit PPM picture (top row first).
 *
 *   headless [-u user] [-p password] [-b bpp] [-z] [-x flags] [-s seconds]
 *            [-o out.ppm] [-k] [-r] host [port]
 *
 *   -z  ask for MPPC compression
 *   -x  performanceFlags, hex (default 2f: no wallpaper, animations, themes)
 *   -k  after activation: type "a" and click at 10,10
 *   -r  after activation: ask for a refresh of the whole screen
 *   -m n  after activation: n mouse moves, each with a refresh of 16 x 16
 *         pixels (with RC4, over 4096 packets each way change the keys)
 *
 * Exit status: 0 = the session became active and ended without error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "ntrdpc.h"

static int sock = -1;
static int was_active, pointers, palettes;
static long invalidates;
static double pixels, t_active;		/* drawn; when the session became active */
static double now(void);

void
ui_send(RDP *r, const u8 *d, int n)
{
	ssize_t k;

	while (n > 0) {
		k = send(sock, d, (size_t)n, 0);
		if (k <= 0) {
			rdp_fail(r, "send failed");
			return;
		}
		d += k;
		n -= (int)k;
	}
}

void
ui_resize(RDP *r)
{
	printf("desktop %dx%d, %d bpp\n", r->fb.w, r->fb.h, r->fb.bpp);
}

void
ui_palette(RDP *r)
{
	(void)r;
	palettes++;
}

void
ui_invalidate(RDP *r, int x, int y, int w, int h)
{
	(void)r;
	if (x < 0 || y < 0 || w <= 0 || h <= 0)
		printf("bad invalidate %d,%d %dx%d\n", x, y, w, h);
	invalidates++;
	pixels += (double)w * h;
}

void
ui_state(RDP *r)
{
	static const char *names[] = { "", "connect", "tls", "nla", "mcs",
		"attach", "join", "license", "demand", "final", "active",
		"done" };

	printf("state %s\n", names[r->state]);
	if (r->state == RS_ACTIVE) {
		was_active = 1;
		t_active = now();
	}
}

void
ui_random(RDP *r, u8 *buf, int len)
{
	FILE *fp = fopen("/dev/urandom", "rb");

	(void)r;
	if (!fp || fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		fprintf(stderr, "no /dev/urandom\n");
		exit(2);
	}
	fclose(fp);
}

void
ui_pointer_new(RDP *r, int index, int hotx, int hoty, const u8 *and,
	       const u8 *rgb)
{
	(void)r;
	(void)and;
	(void)rgb;
	printf("pointer %d, hot spot %d,%d\n", index, hotx, hoty);
	pointers++;
}

void
ui_pointer_cached(RDP *r, int index)
{
	(void)r;
	printf("pointer cached %d\n", index);
}

void
ui_pointer_system(RDP *r, int visible)
{
	(void)r;
	printf("pointer system %s\n", visible ? "default" : "hidden");
}

static void
write_ppm(RDP *r, const char *name)
{
	FBUF *f = &r->fb;
	FILE *fp = fopen(name, "wb");
	int x, y;
	u8 *p;
	u32 v;

	if (!fp || !f->bits) {
		printf("cannot write %s\n", name);
		if (fp)
			fclose(fp);
		return;
	}
	fprintf(fp, "P6\n%d %d\n255\n", f->w, f->h);
	for (y = 0; y < f->h; y++) {
		p = FB_ROW(f, y);
		for (x = 0; x < f->w; x++) {
			switch (f->bpp) {
			case 8:
				fwrite(f->pal[p[x]], 1, 3, fp);
				break;
			case 15:
				v = p[2 * x] | p[2 * x + 1] << 8;
				fputc((int)((v >> 10 & 31) << 3), fp);
				fputc((int)((v >> 5 & 31) << 3), fp);
				fputc((int)((v & 31) << 3), fp);
				break;
			case 16:
				v = p[2 * x] | p[2 * x + 1] << 8;
				fputc((int)((v >> 11 & 31) << 3), fp);
				fputc((int)((v >> 5 & 63) << 2), fp);
				fputc((int)((v & 31) << 3), fp);
				break;
			default:
				fputc(p[3 * x + 2], fp);
				fputc(p[3 * x + 1], fp);
				fputc(p[3 * x], fp);
				break;
			}
		}
	}
	fclose(fp);
	printf("wrote %s\n", name);
}

static double
now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int
dial(const char *host, const char *port)
{
	struct addrinfo hints, *ai;
	int one = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &ai) != 0) {
		fprintf(stderr, "cannot find %s\n", host);
		return 0;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0 || connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		fprintf(stderr, "cannot connect to %s:%s\n", host, port);
		return 0;
	}
	freeaddrinfo(ai);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return 1;
}

int
main(int argc, char **argv)
{
	RDPOPT opt;
	RDP *r;
	struct pollfd pfd;
	const char *host = NULL, *port = "3389", *out = "screen.ppm";
	double seconds = 5, start, t0, t_last = 0, bytes = 0;
	int i, n, keys = 0, refresh = 0, sent = 0, moves = 0;
	u8 buf[65536];

	memset(&opt, 0, sizeof(opt));
	opt.width = 800;
	opt.height = 600;
	opt.bpp = 16;
	opt.keylayout = 0x409;
	opt.perf = PERF_FAST;
	strcpy(opt.client, "HEADLESS");
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-u") && i + 1 < argc)
			strncpy(opt.user, argv[++i], sizeof(opt.user) - 1);
		else if (!strcmp(argv[i], "-p") && i + 1 < argc)
			strncpy(opt.password, argv[++i],
				sizeof(opt.password) - 1);
		else if (!strcmp(argv[i], "-d") && i + 1 < argc)
			strncpy(opt.domain, argv[++i], sizeof(opt.domain) - 1);
		else if (!strcmp(argv[i], "-g") && i + 1 < argc)
			sscanf(argv[++i], "%dx%d", &opt.width, &opt.height);
		else if (!strcmp(argv[i], "-plain"))
			opt.plain = 1;
		else if (!strcmp(argv[i], "-b") && i + 1 < argc)
			opt.bpp = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-s") && i + 1 < argc)
			seconds = atof(argv[++i]);
		else if (!strcmp(argv[i], "-o") && i + 1 < argc)
			out = argv[++i];
		else if (!strcmp(argv[i], "-z"))
			opt.compress = 1;
		else if (!strcmp(argv[i], "-x") && i + 1 < argc)
			opt.perf = (u32)strtoul(argv[++i], NULL, 16);
		else if (!strcmp(argv[i], "-k"))
			keys = 1;
		else if (!strcmp(argv[i], "-r"))
			refresh = 1;
		else if (!strcmp(argv[i], "-m") && i + 1 < argc)
			moves = atoi(argv[++i]);
		else if (!host)
			host = argv[i];
		else
			port = argv[i];
	}
	if (!host) {
		fprintf(stderr, "usage: headless [-u user] [-p password] "
			"[-d domain] [-g WxH] [-plain] [-b bpp] [-z] [-x flags] "
			"[-s seconds] [-o out.ppm] [-k] [-r] [-m moves] "
			"host [port]\n");
		return 2;
	}
	if (!dial(host, port))
		return 2;
	r = rdp_new(&opt, NULL);
	if (!r)
		return 2;
	t0 = now();
	rdp_start(r);
	/* until TLS runs: a server with no TLS, or an older TLS, wants
	   plain RDP (RDP security) */
	for (i = 0; i < 100 && r->state != RS_DONE; i++) {
		pfd.fd = sock;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 100) > 0) {
			n = (int)recv(sock, buf, sizeof(buf), 0);
			if (n <= 0) {
				rdp_closed(r);
				break;
			}
			rdp_recv(r, buf, n);
		}
		if (r->state > RS_TLS)
			break;
	}
	if (r->again) {		/* the server takes plain RDP only */
		printf("again, plain RDP: %s\n", r->err);
		close(sock);
		rdp_free(r);
		opt.plain = 1;
		if (!dial(host, port) || !(r = rdp_new(&opt, NULL)))
			return 2;
		rdp_start(r);
	}
	start = now();
	while (r->state != RS_DONE && now() - start < seconds) {
		pfd.fd = sock;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 100) > 0) {
			n = (int)recv(sock, buf, sizeof(buf), 0);
			if (n <= 0) {
				rdp_closed(r);
				break;
			}
			bytes += n;
			t_last = now();
			rdp_recv(r, buf, n);
		}
		if (r->state == RS_ACTIVE && !sent && now() - start > 1) {
			sent = 1;
			if (keys) {
				rdp_sync(r, 0);
				rdp_key(r, 0, 0x1E);
				rdp_key(r, RK_UP | RK_DOWN, 0x1E);
				rdp_mouse(r, RM_MOVE, 10, 10);
				rdp_mouse(r, RM_B1 | RM_DOWN, 10, 10);
				rdp_mouse(r, RM_B1, 10, 10);
			}
			if (refresh)
				rdp_refresh(r, 0, 0, r->fb.w, r->fb.h);
		}
		if (r->state == RS_ACTIVE && sent && moves > 0) {
			for (i = 0; i < 40 && moves > 0; i++, moves--) {
				rdp_mouse(r, RM_MOVE, 100 + moves % 300, 300);
				rdp_refresh(r, moves % 40 * 16, moves / 40 % 30 *
					    16, 16, 16);
			}
		}
	}
	if (r->state != RS_DONE)
		rdp_close(r);
	printf("ended: %s\n", r->err[0] ? r->err : "(by us)");
	printf("palettes %d, invalidates %ld, pointers %d\n", palettes,
	       invalidates, pointers);
	printf("received %.0f bytes; active after %.2f s; last data at %.2f s; "
	       "%.0f pixels drawn\n", bytes, was_active ? t_active - t0 : 0.0,
	       t_last ? t_last - t0 : 0.0, pixels);
	write_ppm(r, out);
	close(sock);
	n = was_active && !r->err[0] ? 0 : 1;
	rdp_free(r);
	return n;
}
