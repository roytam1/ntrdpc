# An independent model of Standard RDP Security and licensing key math
# (MS-RDPBCGR 5.3, MS-RDPELE 5.1), to make expected values for sectest.c.
import hashlib, struct, subprocess, sys

def md5(*a): return hashlib.md5(b''.join(a)).digest()
def sha1(*a): return hashlib.sha1(b''.join(a)).digest()

def rc4(key, data):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255; s[i], s[j] = s[j], s[i]
    i = j = 0; out = bytearray()
    for c in data:
        i = (i + 1) & 255; j = (j + s[i]) & 255; s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 255])
    return bytes(out)

def salted(s, i, a, b): return md5(s, sha1(i, s, a, b))
def hash48(s, x, a, b):
    l = [b'X', b'YY', b'ZZZ'] if x else [b'A', b'BB', b'CCC']
    return b''.join(salted(s, i, a, b) for i in l)

def salt(method, k):
    k = bytearray(k[:8] if method != 2 else k[:16])
    if method == 1: k[0:3] = b'\xd1\x26\x9e'
    elif method == 8: k[0] = 0xd1
    return bytes(k)

def session(method, cr, sr):
    pre = cr[:24] + sr[:24]
    master = hash48(pre, 0, cr, sr)
    blob = hash48(master, 1, cr, sr)
    mac = salt(method, blob[:16])
    dec = salt(method, md5(blob[16:32], cr, sr))
    enc = salt(method, md5(blob[32:48], cr, sr))
    return mac, enc, dec

def mac(key, data):
    return md5(key, b'\x5c' * 48, sha1(key, b'\x36' * 40, struct.pack('<I', len(data)), data))

def update(method, first, now):
    t = md5(first, b'\x5c' * 48, sha1(first, b'\x36' * 40, now))[:len(now)]
    return salt(method, rc4(t, t))

def rsa_le(n, e, m):
    c = pow(int.from_bytes(m, 'little'), e, n)
    nl = (n.bit_length() + 7) // 8
    return c.to_bytes(nl, 'little') + b'\0' * 8

def hx(b): return b.hex()

cert = open(sys.argv[1], 'rb').read()
mod = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', sys.argv[1], '-noout', '-modulus'],
                     capture_output=True, text=True).stdout.strip().split('=')[1]
n = int(mod, 16); e = 65537
cr = bytes(range(32)); sr = bytes(range(0x80, 0xa0))
data = b'ntrdpc test data'
print('#define T_CERT "%s"' % hx(cert))
print('#define T_N "%s"' % mod.lower())
print('#define T_RSA "%s"' % hx(rsa_le(n, e, cr)))
for m in (1, 8, 2):
    mk, ek, dk = session(m, cr, sr)
    print('#define T_M%d_MAC "%s"' % (m, hx(mk)))
    print('#define T_M%d_ENC "%s"' % (m, hx(ek)))
    print('#define T_M%d_DEC "%s"' % (m, hx(dk)))
    print('#define T_M%d_SIG "%s"' % (m, hx(mac(mk, data)[:8])))
    print('#define T_M%d_CIPHER "%s"' % (m, hx(rc4(ek, data))))
    print('#define T_M%d_UPD "%s"' % (m, hx(update(m, ek, ek))))
# licensing
lsr = bytes(range(0xa0, 0xc0)); lcr = bytes(range(0x20, 0x40)); pre = bytes(range(0x40, 0x70))
master = hash48(pre, 0, lcr, lsr)
blob = hash48(master, 0, lsr, lcr)
lmac = blob[:16]; lkey = md5(blob[16:32], lcr, lsr)
print('#define T_LMAC "%s"' % hx(lmac))
print('#define T_LKEY "%s"' % hx(lkey))
# the server's License Request, with a proprietary certificate of the key n
nl = (n.bit_length() + 7) // 8
rsa1 = b'RSA1' + struct.pack('<IIII', nl + 8, nl * 8, nl - 1, e) + n.to_bytes(nl, 'little') + b'\0' * 8
prop = struct.pack('<IIIHH', 1, 1, 1, 6, len(rsa1)) + rsa1 + struct.pack('<HH', 8, 72) + b'\0' * 72
print('#define T_PROP "%s"' % hx(prop))
req = lsr + struct.pack('<I', 0x60000) + struct.pack('<I', 14) + 'Microsoft\0'.encode('utf-16-le')[:14] \
    + struct.pack('<I', 8) + 'A02\0'.encode('utf-16-le') \
    + struct.pack('<HHI', 0x0d, 4, 1) + struct.pack('<HH', 3, len(prop)) + prop \
    + struct.pack('<I', 1) + struct.pack('<HH', 0x0e, 13) + b'microsoft.com'
print('#define T_LREQ "%s"' % hx(req))
user = b'tenox\0'; machine = b'HEADLESS\0'
nlr = struct.pack('<II', 1, 0x04010000) + lcr + struct.pack('<HH', 2, nl + 8) + rsa_le(n, e, pre) \
    + struct.pack('<HH', 0x0f, len(user)) + user + struct.pack('<HH', 0x10, len(machine)) + machine
print('#define T_NLR "%s"' % hx(struct.pack('<BBH', 0x13, 3, len(nlr) + 4) + nlr))
# the Platform Challenge and the answer
chal = 'TEST\0'.encode('utf-16-le')
pc = struct.pack('<I', 0) + struct.pack('<HH', 9, len(chal)) + rc4(lkey, chal) + mac(lmac, chal)
print('#define T_CHAL "%s"' % hx(pc))
d = struct.pack('<HHHH', 0x100, 0xff00, 3, len(chal)) + chal
hwid = struct.pack('<I', 0x04010000) + md5(b'HEADLESS')
resp = struct.pack('<HH', 9, len(d)) + rc4(lkey, d) + struct.pack('<HH', 9, 20) + rc4(lkey, hwid) + mac(lmac, d + hwid)
print('#define T_RESP "%s"' % hx(struct.pack('<BBH', 0x15, 3, len(resp) + 4) + resp))
