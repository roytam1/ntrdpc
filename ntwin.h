/*
 * ntwin.h - what window.c and dialog.c share: the settings of a connection.
 * Include it after windows.h.
 */

#ifndef NTWIN_H
#define NTWIN_H

typedef struct {
	char host[256];			/* computer[:port], as typed */
	char user[64];
	char password[64];		/* never stored on disk */
	char domain[64];
	int bpp;			/* most colors: 8, 15, 16 or 24 */
	int full;			/* full screen */
	int width, height;		/* desktop size to ask for; 0 = auto */
	int effects;			/* wallpaper and animations: -e */
} CONFIG;

/* dialog.c */
void cfg_defaults(CONFIG *c);
void cfg_load(CONFIG *c);
void cfg_save(const CONFIG *c);
int cfg_args(CONFIG *c, const char *cmdline);
int dlg_connect(HINSTANCE hinst, CONFIG *c, const char *msg);

#endif
