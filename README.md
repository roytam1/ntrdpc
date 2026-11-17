# ntrdpc

An RDP client for Windows NT 3.1, 3.5, 3.51 and 4.0, on Intel, MIPS, Alpha and PowerPC,
and for PINT (Windows NT on the Raspberry Pi).
It is made for ntrdps, the RDP server for the NT console.
It also connects to the RDP server of Windows (Windows 2000 to Windows 11).

**Warning:** ntrdpc does not check the server's certificate.
The old encryption of Windows 2000 to 2003 (RC4) is weak.
Plain RDP (ntrdps with TLS turned off) is not encrypted: the password goes over the network as plain text.
Use ntrdpc only on a network you trust.

## Download

Take the exe for your NT version and CPU from the [releases](https://github.com/tenox7/ntrdpc/releases).

## Use

Start `ntrdpc.exe`. Type the computer, your user name and your password.
Pick the colors and the resolution ("Full screen" is the first one). Press Connect.
Or start it with the computer on the command line. Then it connects at once:

```
ntrdpc computer[:port] [-u user] [-p password] [-d domain] [-b 8|15|16|24] [-f] [-g 800x600] [-e]
```

| Option | What it does |
|---|---|
| `-b` | The most colors to ask for: 8 (256 colors), 15, 16 or 24 bit. ntrdps sends the color depth of its own screen if it is allowed, else 256 colors. Default: 256 colors if this screen shows 256 colors or less, else 24 bit. |
| `-f` | Full screen, at the size of this screen. |
| `-g` | The desktop size to ask for. Windows servers use it. ntrdps always sends its own screen size. |
| `-e` | Effects: the wallpaper, animations, themes, window contents while dragging, the pointer shadow. Without `-e`, ntrdpc asks Windows to leave them out: the screen comes much faster. |

| Keys | What they do |
|---|---|
| Ctrl+Alt+Enter | Full screen on or off. |
| Ctrl+Alt+End | Sends Ctrl+Alt+Del to the server. |

The window menu (click the icon in the corner) also has Ctrl+Alt+Del, Full screen and About.
ntrdpc remembers the computer, the user, the domain, the colors and the resolution (in `HKEY_CURRENT_USER\Software\ntrdpc`).
It never stores the password.

## Build

Open a command prompt where the compiler works (the Win32 SDK or Visual C++). Go to the ntrdpc folder. Type `build`.

| Compiler | Runs on | ntrdpc.exe runs on |
|---|---|---|
| Win32 SDK of July 1993 (`cl386`, `mcl`, `claxp`) | NT 3.1 | NT 3.1 and later |
| Visual C++ 2.0 to 4.2 (`cl`) | NT 3.5 and later | NT 3.5 and later |

`build` finds the compiler on the PATH and the CPU in `PROCESSOR_ARCHITECTURE`.
`build clean` deletes what the build made.
Without `build.cmd`: `nmake TOOLS=sdk31 CPU=i386` (or `MIPS`, `ALPHA`), or `nmake TOOLS=vc CPU=i386` (or `MIPS`, `ALPHA`, `PPC`).

For PINT, Windows NT on the Raspberry Pi, build with the PINT SDK in Docker
([tenox7/pint40sdk](https://hub.docker.com/r/tenox7/pint40sdk) for PINT 4.0,
[tenox7/pint35sdk](https://hub.docker.com/r/tenox7/pint35sdk) for PINT 3.5;
its page tells how to set it up once):

```
docker run --rm -v msvc-arm32:/opt/msvc -v "$PWD":/src tenox7/pint40sdk nmake TOOLS=pint
```

## Files

| File | What it is |
|---|---|
| `rdp.c`, `orders.c`, `draw.c`, `bitmap.c`, `mppc.c`, `ntrdpc.h` | The RDP core in plain C. It knows nothing about Windows. |
| `tls.c`, `nla.c`, `sec.c`, `crypt.c` | The encryption, also plain C: TLS 1.2, NLA (the server checks the password before the session starts), and the old RC4 encryption of Windows 2000 to 2003. |
| `bearssl/` | BearSSL, a small TLS library (MIT license). |
| `window.c`, `dialog.c`, `ntwin.h`, `ntrdpc.rc`, `resource.h`, `ntrdpc.ico` | The Windows part: the window, the keyboard and mouse, the connect dialog. |
| `makefile`, `build.cmd` | The build. |
| `test/` | Tests. They run on a Mac or Unix (`make -C test check`); `replay`, `nlatest` and `sectest` also on NT (the makefile targets `replay.exe`, `nlatest.exe`, `sectest.exe`). |
