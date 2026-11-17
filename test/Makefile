# test/Makefile - the Unix test tools of ntrdpc: make -C test
#   headless   connects to an RDP server, writes the screen as a PPM file
#   replay     draws recorded server packets (for crosscheck.py)
#   nlatest    checks crypt.c's MD4, MD5, HMAC-MD5, RC4 and nla.c's NTLMv2
#              with the examples of RFC 1320, RFC 1321, RFC 2202, MS-NLMP 4.2.4
#   sectest    checks crypt.c's SHA-1 and sec.c (RC4 security, licensing)
#              with FIPS 180 and secvals.h (made by secmodel.py sectest.der)
# The scripts crosscheck.py, fakeserver.py and winetest.py need ../NTRDPS
# (rdpcheck). winetest.py DIR runs DIR/ntrdpc.exe under Wine (nt31sdk image).

CC = cc
CFLAGS = -std=c89 -pedantic -Wall -Wextra -Wno-unused-parameter -O1 -g \
	-I.. -I../bearssl/inc -Dinline=__inline__
CORE = ../rdp.c ../orders.c ../draw.c ../bitmap.c ../mppc.c ../tls.c ../nla.c \
	../crypt.c ../sec.c
HDRS = ../ntrdpc.h
BRSRC = $(wildcard ../bearssl/src/*.c)

all: headless replay nlatest sectest

# BearSSL is third-party C99: its own flags, no warnings
bearssl.a: $(BRSRC)
	rm -rf br bearssl.a
	mkdir br
	for f in $(BRSRC); do \
		$(CC) -c -O1 -w -I../bearssl/inc -I../bearssl/src \
			-o br/`basename $$f .c`.o $$f || exit 1; \
	done
	ar rcs bearssl.a br/*.o

headless: headless.c $(CORE) $(HDRS) bearssl.a
	$(CC) $(CFLAGS) -o $@ headless.c $(CORE) bearssl.a

replay: replay.c $(CORE) $(HDRS) bearssl.a
	$(CC) $(CFLAGS) -o $@ replay.c $(CORE) bearssl.a

nlatest: nlatest.c ../nla.c ../crypt.c $(HDRS) bearssl.a
	$(CC) $(CFLAGS) -o $@ nlatest.c ../crypt.c bearssl.a

sectest: sectest.c secvals.h ../sec.c ../tls.c ../crypt.c $(HDRS) bearssl.a
	$(CC) $(CFLAGS) -Wno-overlength-strings -o $@ sectest.c ../crypt.c \
		bearssl.a

check: all
	./nlatest
	./sectest
	python3 -I fakeserver.py --orders -k -r
	python3 -I crosscheck.py 30

clean:
	rm -rf headless replay nlatest sectest bearssl.a br
