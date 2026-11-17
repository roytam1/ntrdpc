/*
 * dialog.c - the connect dialog, the command line, and the settings in
 * HKEY_CURRENT_USER\Software\ntrdpc (never the password).
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntwin.h"
#include "resource.h"

#ifndef WM_SETICON
#define WM_SETICON	0x0080		/* NT 4.0 only; NT 3.x ignores it */
#endif
#ifndef ICON_BIG
#define ICON_BIG	1		/* Visual C++ 4.1 has WM_SETICON only */
#endif

#define REGKEY	"Software\\ntrdpc"

static const int depths[4] = { 8, 15, 16, 24 };
static const char *const depth_names[4] = {
	"256 colors", "15 bit", "16 bit", "24 bit"
};

/* the Resolution list; "Full screen" comes first */
static const int sizes[][2] = {
	{ 640, 480 }, { 800, 600 }, { 1024, 768 }, { 1152, 864 },
	{ 1280, 720 }, { 1280, 1024 }, { 1600, 1200 }, { 1920, 1080 }
};
#define NSIZES	((int)(sizeof(sizes) / sizeof(sizes[0])))

static HINSTANCE dlg_hinst;
static CONFIG *dlg_cfg;
static const char *dlg_msg;

static void
copy(char *to, const char *from, int size)
{
	strncpy(to, from, size - 1);
	to[size - 1] = 0;
}

/* 8 if the screen shows 256 colors or less, else 24: then ntrdps sends
   its own depth */
static int
screen_bpp(void)
{
	HDC dc = GetDC(NULL);
	int n = 24;

	if (dc) {
		if (GetDeviceCaps(dc, BITSPIXEL) * GetDeviceCaps(dc, PLANES) <= 8)
			n = 8;
		ReleaseDC(NULL, dc);
	}
	return n;
}

void
cfg_defaults(CONFIG *c)
{
	memset(c, 0, sizeof(*c));
	c->bpp = screen_bpp();
}

static void
get_str(HKEY k, const char *name, char *buf, int size)
{
	char tmp[256];
	DWORD type, n = sizeof(tmp);

	if (RegQueryValueEx(k, (LPSTR)name, NULL, &type, (LPBYTE)tmp, &n) ==
	    ERROR_SUCCESS && type == REG_SZ) {
		tmp[sizeof(tmp) - 1] = 0;
		copy(buf, tmp, size);
	}
}

static void
get_int(HKEY k, const char *name, int *v)
{
	DWORD type, d, n = sizeof(d);

	if (RegQueryValueEx(k, (LPSTR)name, NULL, &type, (LPBYTE)&d, &n) ==
	    ERROR_SUCCESS && type == REG_DWORD)
		*v = (int)d;
}

void
cfg_load(CONFIG *c)
{
	HKEY k;
	int i;

	if (RegOpenKeyEx(HKEY_CURRENT_USER, REGKEY, 0, KEY_READ, &k) !=
	    ERROR_SUCCESS)
		return;
	get_str(k, "Computer", c->host, sizeof(c->host));
	get_str(k, "User", c->user, sizeof(c->user));
	get_str(k, "Domain", c->domain, sizeof(c->domain));
	get_int(k, "Colors", &c->bpp);
	get_int(k, "FullScreen", &c->full);
	get_int(k, "Width", &c->width);
	get_int(k, "Height", &c->height);
	RegCloseKey(k);
	for (i = 0; i < 4 && depths[i] != c->bpp; i++)
		;
	if (i == 4)
		c->bpp = screen_bpp();
	c->full = c->full != 0;
	if (c->full || c->width < 64 || c->width > 4096 || c->height < 64 ||
	    c->height > 4096)
		c->width = c->height = 0;
}

static void
set_str(HKEY k, const char *name, const char *s)
{
	RegSetValueEx(k, (LPSTR)name, 0, REG_SZ, (LPBYTE)s,
		      (DWORD)strlen(s) + 1);
}

static void
set_int(HKEY k, const char *name, int v)
{
	DWORD d = (DWORD)v;

	RegSetValueEx(k, (LPSTR)name, 0, REG_DWORD, (LPBYTE)&d, sizeof(d));
}

void
cfg_save(const CONFIG *c)
{
	HKEY k;
	DWORD disp;

	if (RegCreateKeyEx(HKEY_CURRENT_USER, REGKEY, 0, (LPSTR)"",
			   REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &k,
			   &disp) != ERROR_SUCCESS)
		return;
	set_str(k, "Computer", c->host);
	set_str(k, "User", c->user);
	set_str(k, "Domain", c->domain);
	set_int(k, "Colors", c->bpp);
	set_int(k, "FullScreen", c->full);
	set_int(k, "Width", c->width);
	set_int(k, "Height", c->height);
	RegCloseKey(k);
}

/* the next word of the command line; "" quotes may hold spaces */
static int
next_arg(const char **p, char *buf, int size)
{
	const char *s = *p;
	int n = 0, quote = 0;

	while (*s == ' ' || *s == '\t')
		s++;
	if (!*s)
		return 0;
	while (*s && (quote || (*s != ' ' && *s != '\t'))) {
		if (*s == '"')
			quote = !quote;
		else if (n < size - 1)
			buf[n++] = *s;
		s++;
	}
	buf[n] = 0;
	*p = s;
	return 1;
}

/*
 * ntrdpc [computer[:port]] [-u user] [-p password] [-d domain]
 *        [-b 8|15|16|24] [-f] [-g WIDTHxHEIGHT] [-e]
 * Returns 1 when a computer is given (connect at once), 0 when not
 * (show the dialog), -1 for a wrong command line.
 */
int
cfg_args(CONFIG *c, const char *cmdline)
{
	const char *p = cmdline;
	char a[256], v[256];
	int host = 0, size = 0;

	while (next_arg(&p, a, sizeof(a))) {
		if (a[0] != '-' && a[0] != '/') {
			if (host)
				goto usage;
			copy(c->host, a, sizeof(c->host));
			host = 1;
			continue;
		}
		if (!a[1] || a[2])
			goto usage;
		if (a[1] == 'f' || a[1] == 'F') {
			c->full = 1;
			continue;
		}
		if (a[1] == 'e' || a[1] == 'E') {
			c->effects = 1;
			continue;
		}
		if (!next_arg(&p, v, sizeof(v)))
			goto usage;
		switch (a[1]) {
		case 'u':
		case 'U':
			copy(c->user, v, sizeof(c->user));
			break;
		case 'p':
		case 'P':
			copy(c->password, v, sizeof(c->password));
			break;
		case 'd':
		case 'D':
			copy(c->domain, v, sizeof(c->domain));
			break;
		case 'b':
		case 'B':
			c->bpp = atoi(v);
			if (c->bpp != 8 && c->bpp != 15 && c->bpp != 16 &&
			    c->bpp != 24)
				goto usage;
			break;
		case 'g':
		case 'G':
			if (sscanf(v, "%dx%d", &c->width, &c->height) != 2 ||
			    c->width < 64 || c->width > 4096 ||
			    c->height < 64 || c->height > 4096)
				goto usage;
			size = 1;
			break;
		default:
			goto usage;
		}
	}
	if (c->full && !size)		/* -f: the screen's size */
		c->width = c->height = 0;
	return host;
usage:
	MessageBox(NULL, "ntrdpc [computer[:port]] [-u user] [-p password]\n"
		   "    [-d domain] [-b 8|15|16|24] [-f] [-g 800x600] [-e]\n\n"
		   "-b  most colors\n"
		   "-f  full screen\n"
		   "-g  desktop size\n"
		   "-e  wallpaper and animations", "ntrdpc",
		   MB_OK | MB_ICONINFORMATION);
	return -1;
}

static void
trim(char *s)
{
	char *p = s;
	int n;

	while (*p == ' ')
		p++;
	memmove(s, p, strlen(p) + 1);
	n = (int)strlen(s);
	while (n > 0 && s[n - 1] == ' ')
		s[--n] = 0;
}

static void
center(HWND d)
{
	RECT rc;
	int w, h;

	GetWindowRect(d, &rc);
	w = rc.right - rc.left;
	h = rc.bottom - rc.top;
	SetWindowPos(d, NULL, (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
		     (GetSystemMetrics(SM_CYSCREEN) - h) / 3, 0, 0,
		     SWP_NOSIZE | SWP_NOZORDER);
}

/* fills the Resolution list and picks the size of c */
static void
init_sizes(HWND d, const CONFIG *c)
{
	char buf[32];
	int i, sel = -1;

	SendDlgItemMessage(d, IDC_RES, CB_ADDSTRING, 0, (LPARAM)"Full screen");
	for (i = 0; i < NSIZES; i++) {
		sprintf(buf, "%d x %d", sizes[i][0], sizes[i][1]);
		SendDlgItemMessage(d, IDC_RES, CB_ADDSTRING, 0, (LPARAM)buf);
		if (sizes[i][0] == c->width && sizes[i][1] == c->height)
			sel = i + 1;
	}
	if (c->full)
		sel = 0;
	else if (sel < 0 && c->width) {		/* -g with another size */
		sprintf(buf, "%d x %d", c->width, c->height);
		SendDlgItemMessage(d, IDC_RES, CB_ADDSTRING, 0, (LPARAM)buf);
		sel = NSIZES + 1;
	} else if (sel < 0)	/* not chosen yet: 800 x 600, or full screen
				   on a smaller screen */
		sel = GetSystemMetrics(SM_CXSCREEN) < 800 ||
		      GetSystemMetrics(SM_CYSCREEN) < 600 ? 0 : 2;
	SendDlgItemMessage(d, IDC_RES, CB_SETCURSEL, sel, 0);
}

static BOOL CALLBACK
dlgproc(HWND d, UINT msg, WPARAM wp, LPARAM lp)
{
	CONFIG *c = dlg_cfg;
	int i, focus;

	(void)lp;
	switch (msg) {
	case WM_INITDIALOG:
		SendMessage(d, WM_SETICON, ICON_BIG,
			    (LPARAM)LoadIcon(dlg_hinst,
					     MAKEINTRESOURCE(IDI_NTRDPC)));
		SetDlgItemText(d, IDC_MESSAGE, dlg_msg ? dlg_msg : "");
		SetDlgItemText(d, IDC_HOST, c->host);
		SetDlgItemText(d, IDC_USER, c->user);
		SetDlgItemText(d, IDC_PASS, c->password);
		SetDlgItemText(d, IDC_DOMAIN, c->domain);
		SendDlgItemMessage(d, IDC_HOST, EM_LIMITTEXT,
				   sizeof(c->host) - 1, 0);
		SendDlgItemMessage(d, IDC_USER, EM_LIMITTEXT,
				   sizeof(c->user) - 1, 0);
		SendDlgItemMessage(d, IDC_PASS, EM_LIMITTEXT,
				   sizeof(c->password) - 1, 0);
		SendDlgItemMessage(d, IDC_DOMAIN, EM_LIMITTEXT,
				   sizeof(c->domain) - 1, 0);
		for (i = 0; i < 4; i++) {
			SendDlgItemMessage(d, IDC_COLORS, CB_ADDSTRING, 0,
					   (LPARAM)depth_names[i]);
			if (depths[i] == c->bpp)
				SendDlgItemMessage(d, IDC_COLORS,
						   CB_SETCURSEL, i, 0);
		}
		init_sizes(d, c);
		center(d);
		focus = !c->host[0] ? IDC_HOST : !c->user[0] ? IDC_USER :
			IDC_PASS;
		SetFocus(GetDlgItem(d, focus));
		SendDlgItemMessage(d, focus, EM_SETSEL, 0, -1);
		return FALSE;		/* we set the focus */
	case WM_COMMAND:
		switch (LOWORD(wp)) {
		case IDOK:
			GetDlgItemText(d, IDC_HOST, c->host, sizeof(c->host));
			trim(c->host);
			if (!c->host[0]) {
				MessageBeep(0);
				SetFocus(GetDlgItem(d, IDC_HOST));
				return TRUE;
			}
			GetDlgItemText(d, IDC_USER, c->user, sizeof(c->user));
			GetDlgItemText(d, IDC_PASS, c->password,
				       sizeof(c->password));
			GetDlgItemText(d, IDC_DOMAIN, c->domain,
				       sizeof(c->domain));
			trim(c->user);
			trim(c->domain);
			i = (int)SendDlgItemMessage(d, IDC_COLORS,
						    CB_GETCURSEL, 0, 0);
			if (i >= 0 && i < 4)
				c->bpp = depths[i];
			i = (int)SendDlgItemMessage(d, IDC_RES, CB_GETCURSEL,
						    0, 0);
			if (i == 0) {
				c->full = 1;
				c->width = c->height = 0;
			} else if (i > 0) {
				c->full = 0;
				if (i <= NSIZES) {
					c->width = sizes[i - 1][0];
					c->height = sizes[i - 1][1];
				}	/* else the size of -g stays */
			}
			cfg_save(c);
			EndDialog(d, 1);
			return TRUE;
		case IDCANCEL:
			EndDialog(d, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

/* 1 = connect; msg: why the last session ended, or NULL */
int
dlg_connect(HINSTANCE hinst, CONFIG *c, const char *msg)
{
	dlg_hinst = hinst;
	dlg_cfg = c;
	dlg_msg = msg;
	return DialogBox(hinst, MAKEINTRESOURCE(IDD_CONNECT), NULL,
			 (DLGPROC)dlgproc) == 1;
}
