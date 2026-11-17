# makefile - ntrdpc.exe, the RDP client for Windows NT 3.1 - 4.0.
# build.cmd runs it with the right TOOLS and CPU. By hand:
#   nmake TOOLS=sdk31 CPU=i386   Win32 SDK of 1993 (NT 3.1): cl386, link32
#   nmake TOOLS=sdk31 CPU=MIPS   the same for MIPS: mcl
#   nmake TOOLS=sdk31 CPU=ALPHA  the same for Alpha: claxp
#   nmake TOOLS=vc CPU=i386      Visual C++ 2.0 - 4.2: cl, link
#                                (also CPU=MIPS, ALPHA or PPC)
#   nmake TOOLS=pint             PINT, Windows NT on the Raspberry Pi: in Docker,
#                                tenox7/pint35sdk or tenox7/pint40sdk (README)
#   nmake TOOLS=... CPU=... clean
#   nmake TOOLS=... CPU=... replay.exe   test program: "replay -m cases.bin"
#                                checks the RDP core as this compiler built it
#                                (test/crosscheck.py --export makes cases.bin)
#   nmake TOOLS=... CPU=... nlatest.exe sectest.exe   test programs: they
#                                check the crypto as this compiler built it
# An exe of TOOLS=sdk31 runs on NT 3.1 and later. One of TOOLS=vc is marked
# 3.10 and runs on NT 3.5 and later.
# Only "!IF" and "!ENDIF", no "!ELSEIF": nmake 1.12 of NT 3.1 reads it.
# Own macros start with N_, so none of them is an environment variable.

# TLS: BearSSL (bearssl\README.txt), 45 files of it.
N_BR = bearssl\src\aes_ct_ctr.obj bearssl\src\aes_ct_enc.obj \
        bearssl\src\aes_ct.obj bearssl\src\ccopy.obj bearssl\src\dec32be.obj \
        bearssl\src\ec_p256_m15.obj bearssl\src\ec_secp256r1.obj \
        bearssl\src\ec_secp384r1.obj bearssl\src\ec_secp521r1.obj \
        bearssl\src\ecdsa_atr.obj bearssl\src\ecdsa_i15_bits.obj \
        bearssl\src\ecdsa_i15_vrfy_asn1.obj bearssl\src\ecdsa_i15_vrfy_raw.obj \
        bearssl\src\enc32be.obj bearssl\src\ghash_ctmul32.obj \
        bearssl\src\hmac_drbg.obj bearssl\src\hmac.obj bearssl\src\i15_add.obj \
        bearssl\src\i15_bitlen.obj bearssl\src\i15_decmod.obj \
        bearssl\src\i15_decode.obj bearssl\src\i15_encode.obj \
        bearssl\src\i15_fmont.obj bearssl\src\i15_iszero.obj \
        bearssl\src\i15_modpow.obj bearssl\src\i15_modpow2.obj \
        bearssl\src\i15_montmul.obj bearssl\src\i15_muladd.obj \
        bearssl\src\i15_ninv15.obj bearssl\src\i15_rshift.obj \
        bearssl\src\i15_sub.obj bearssl\src\i15_tmont.obj \
        bearssl\src\multihash.obj bearssl\src\prf_sha256.obj bearssl\src\prf.obj \
        bearssl\src\rsa_i15_pkcs1_vrfy.obj bearssl\src\rsa_i15_pub.obj \
        bearssl\src\rsa_pkcs1_sig_unpad.obj bearssl\src\sha2small.obj \
        bearssl\src\ssl_client.obj bearssl\src\ssl_engine.obj \
        bearssl\src\ssl_hs_client.obj bearssl\src\ssl_rec_gcm.obj \
        bearssl\src\sysrng.obj bearssl\src\x509_decoder.obj

N_CORE = rdp.obj orders.obj draw.obj bitmap.obj mppc.obj tls.obj nla.obj \
        crypt.obj sec.obj \
        $(N_BR)
N_OBJS = window.obj dialog.obj $(N_CORE)
N_LIBS = kernel32.lib user32.lib gdi32.lib advapi32.lib wsock32.lib
# The C run-time: libc, single-threaded; for PINT libcmt, the run-time of its SDKs
N_CRT = libc.lib

# The 1993 compilers for MIPS and Alpha go wrong with -Ox: -Od there.
# link32 takes no .res file: cvtres makes it an object (.rbj) first.
# They have no 64-bit integer: BearSSL takes bearssl\nt31\stdint.h.
!IF "$(TOOLS)" == "sdk31"
N_LINK = link32 -subsystem:windows -entry:WinMainCRTStartup $(N_ALIGN)
N_LINKC = link32 -subsystem:console -entry:mainCRTStartup $(N_ALIGN)
N_RES = ntrdpc.rbj
N_BRINC = -Ibearssl\inc -Ibearssl\nt31 -DBR_NT31 -Dinline=__inline
!IF "$(CPU)" == "i386"
N_CC = cl386 -c -W3 -Ox -D_X86_=1 -DWIN32
N_BRCC = cl386 -c -W0 -Od -D_X86_=1 -DWIN32
N_ALIGN = -align:0x1000
!ENDIF
!IF "$(CPU)" == "MIPS"
N_CC = mcl -c -W3 -Od -D_MIPS_=1 -DWIN32
N_BRCC = mcl -c -W0 -Od -D_MIPS_=1 -DWIN32
!ENDIF
!IF "$(CPU)" == "ALPHA"
N_CC = claxp -c -W3 -Od -D_ALPHA_=1 -DWIN32
N_BRCC = claxp -c -W0 -Od -D_ALPHA_=1 -DWIN32
!ENDIF
!ENDIF

# Visual C++ 4 marks 4.00, which NT 3.51 does not run: 3.10.
# Both MIPS compilers make wrong code when they optimize (PuTTY for NT,
# 2026-11): -Od on MIPS. BearSSL: -Od everywhere, as in ntrdps.
!IF "$(TOOLS)" == "vc"
N_LINK = link -nologo -subsystem:windows,3.10
N_LINKC = link -nologo -subsystem:console,3.10
N_RES = ntrdpc.res
N_CFLAGS = -nologo -c -W3 -DWIN32 -D_WIN32
N_BRFLAGS = -nologo -c -W0 -Od -DWIN32 -D_WIN32
N_BRINC = -Ibearssl\inc -Ibearssl\compat -Dinline=__inline
!IF "$(CPU)" == "i386"
N_CC = cl $(N_CFLAGS) -Ox -D_X86_=1
N_BRCC = cl $(N_BRFLAGS) -D_X86_=1
!ENDIF
!IF "$(CPU)" == "MIPS"
N_CC = cl $(N_CFLAGS) -Od -D_MIPS_=1
N_BRCC = cl $(N_BRFLAGS) -D_MIPS_=1
!ENDIF
!IF "$(CPU)" == "ALPHA"
N_CC = cl $(N_CFLAGS) -Ox -D_ALPHA_=1
N_BRCC = cl $(N_BRFLAGS) -D_ALPHA_=1
!ENDIF
!IF "$(CPU)" == "PPC"
N_CC = cl $(N_CFLAGS) -Ox -D_PPC_=1
N_BRCC = cl $(N_BRFLAGS) -D_PPC_=1
!ENDIF
!ENDIF

# PINT: Microsoft C for ARM of the PINT 3.5 or 4.0 SDK, whose cl and link mark the exe for its NT.
!IF "$(TOOLS)" == "pint"
N_LINK = link -nologo -subsystem:windows
N_LINKC = link -nologo -subsystem:console
N_RES = ntrdpc.res
N_CRT = libcmt.lib
N_CC = cl -nologo -c -W3 -Ox -DWIN32 -D_WIN32
N_BRCC = cl -nologo -c -W0 -Od -DWIN32 -D_WIN32
N_BRINC = -Ibearssl\inc -Ibearssl\compat -Dinline=__inline
!ENDIF

!IFNDEF N_CC
!ERROR Run build.cmd, or give TOOLS=sdk31 or TOOLS=vc, and CPU=i386, MIPS, ALPHA or PPC, or TOOLS=pint.
!ENDIF

all: ntrdpc.exe

# The object list is long: it goes in a response file.
ntrdpc.exe: $(N_OBJS) $(N_RES)
	$(N_LINK) -out:ntrdpc.exe @<<
$(N_OBJS) $(N_RES) $(N_CRT) $(N_LIBS)
<<

.c.obj:
	$(N_CC) $<

{bearssl\src}.c{bearssl\src}.obj:
	$(N_BRCC) $(N_BRINC) -Ibearssl\src -DBR_USE_WIN32_RAND=0 -Fo$@ $<

window.obj: window.c ntrdpc.h ntwin.h resource.h
dialog.obj: dialog.c ntwin.h resource.h
rdp.obj: rdp.c ntrdpc.h
orders.obj: orders.c ntrdpc.h
draw.obj: draw.c ntrdpc.h
bitmap.obj: bitmap.c ntrdpc.h
mppc.obj: mppc.c ntrdpc.h

tls.obj: tls.c ntrdpc.h
	$(N_CC) $(N_BRINC) tls.c

nla.obj: nla.c ntrdpc.h
	$(N_CC) $(N_BRINC) nla.c

crypt.obj: crypt.c ntrdpc.h

sec.obj: sec.c ntrdpc.h
	$(N_CC) $(N_BRINC) sec.c

replay.exe: replay.obj $(N_CORE)
	$(N_LINKC) -out:replay.exe @<<
replay.obj $(N_CORE) $(N_CRT) kernel32.lib
<<

replay.obj: test\replay.c ntrdpc.h
	$(N_CC) -I. test\replay.c

nlatest.exe: nlatest.obj crypt.obj $(N_BR)
	$(N_LINKC) -out:nlatest.exe @<<
nlatest.obj crypt.obj $(N_BR) $(N_CRT) kernel32.lib
<<

nlatest.obj: test\nlatest.c nla.c ntrdpc.h
	$(N_CC) $(N_BRINC) -I. test\nlatest.c

sectest.exe: sectest.obj crypt.obj $(N_BR)
	$(N_LINKC) -out:sectest.exe @<<
sectest.obj crypt.obj $(N_BR) $(N_CRT) kernel32.lib
<<

sectest.obj: test\sectest.c test\secvals.h tls.c sec.c ntrdpc.h
	$(N_CC) $(N_BRINC) -I. test\sectest.c

ntrdpc.res: ntrdpc.rc resource.h ntrdpc.ico
	rc -r -DWIN32 -fo ntrdpc.res ntrdpc.rc

ntrdpc.rbj: ntrdpc.res
	cvtres -$(CPU) ntrdpc.res -o ntrdpc.rbj

clean:
	-del *.obj
	-del bearssl\src\*.obj
	-del ntrdpc.res
	-del ntrdpc.rbj
	-del ntrdpc.exe
	-del replay.exe
	-del nlatest.exe
	-del sectest.exe
