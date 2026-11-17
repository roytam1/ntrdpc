BearSSL for ntrdpc - the TLS of ntrdpc

TL;DR: 45 files of BearSSL (https://bearssl.org/), copied from ntrdps
(../NTRDPS/src/tls/bearssl) on 2026-11-15. MIT license: LICENSE.txt.

- Upstream: BearSSL git 7bea48e (2026-04-06), the same copy as in ntrdps.
- The files are the ones ntrdps uses, with ntrdps's change for the 1993
  compilers: with BR_NT31, uint64_t is a pair of 32-bit halves
  (nt31/stdint.h, src/inner.h). Only the line ends changed (CRLF).
- What ntrdpc uses: a TLS 1.2 client. Suites ECDHE_RSA, ECDHE_ECDSA and RSA,
  each with AES_128_GCM_SHA256; the curve P-256; the small i15 math.
  The code that sets this up is ../tls.c. ../sec.c (the old RC4
  security of RDP) uses its RSA too.

Folders:
  inc/     the public headers
  src/     the .c files, inner.h, config.h
  nt31/    stdint.h for cl386, mcl and claxp (no 64-bit integer)
  compat/  stdint.h for Visual C++ 2.0 - 4.2 (they have none)

Build flags (../makefile): -W0 -Od -Dinline=__inline -DBR_USE_WIN32_RAND=0;
the 1993 compilers also -DBR_NT31 -Ibearssl\nt31. ntrdpc gives BearSSL its
own random bytes (ui_random in ../window.c), so NT 3.1 needs no CryptoAPI.
