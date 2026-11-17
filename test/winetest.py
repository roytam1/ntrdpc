"""winetest.py - starts ntrdpc.exe under Wine (the nt31sdk image, no display:
Wine's null driver) against a recorded session of the ntrdps fake server.

    make -C test
    python3 -I test/winetest.py DIR

DIR: a folder with ntrdpc.exe (a scratch copy, not the share). The script
records a session of rdpcheck's FakeServer (256 x 192, tiles and orders, a
pointer) with test/headless, plays it to ntrdpc.exe in the container, and
checks: every packet of the connection came, the window painted all 192
lines, the pointer became a cursor, and the end dialog says that the server
closed the connection. It cannot show the picture: check that on NT.
The ntrdps folder: ../NTRDPS or $NTRDPS. The image wrapper: $NT31, else the
nt31sdk skill in ~/.claude/skills.
"""
import os
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NTRDPS = os.environ.get('NTRDPS') or os.path.join(HERE, '..', '..', 'NTRDPS')
NT31 = os.environ.get('NT31') or os.path.expanduser('~/.claude/skills/nt31sdk/scripts/nt31')
sys.path.insert(0, os.path.join(NTRDPS, 'tools', 'rdpcheck'))
import rdpcheck as R    # noqa: E402

EXPECT = ['x224-cr', 'mcs-ci', 'mcs-edrq', 'mcs-aurq', 'mcs-cjrq', 'mcs-cjrq', 'client-info',
          'confirm-active', 'sync', 'control', 'control', 'fontlist', 'input']
RELAY = ('SetDIBitsToDevice;CreateCursor;BeginPaint;CreateWindowExA;ShowWindow;'
         'SetWindowTextA;DialogBoxParamA;SetDlgItemTextA;SetCursor')


def record(path):
    """A FakeServer session through a proxy: (client packets so far, server bytes)."""
    srv = R.FakeServer(256, 192, None, orders=True)
    srv.start()
    ls = socket.socket()
    ls.bind(('127.0.0.1', 0))
    ls.listen(1)
    tmp = tempfile.mkdtemp()
    p = subprocess.Popen([os.path.join(HERE, 'headless'), '-s', '3', '-o',
                          os.path.join(tmp, 'x.ppm'), '127.0.0.1', str(ls.getsockname()[1])],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    c, _ = ls.accept()
    s = socket.create_connection(('127.0.0.1', srv.port))
    cbuf, npkt, recs = b'', 0, []
    while True:
        r, _, _ = select.select([c, s], [], [], 15)
        if not r:
            break
        if c in r:
            d = c.recv(65536)
            if not d:
                break
            s.sendall(d)
            cbuf += d
            while len(cbuf) >= 4 and len(cbuf) >= struct.unpack('>H', cbuf[2:4])[0]:
                cbuf = cbuf[struct.unpack('>H', cbuf[2:4])[0]:]
                npkt += 1
        if s in r:
            d = s.recv(65536)
            if not d:
                break
            recs.append((npkt, d))
            c.sendall(d)
    c.close()
    s.close()
    p.wait()
    srv.join(5)
    if srv.error:
        sys.exit('winetest: recording failed: %s' % srv.error)
    with open(path, 'wb') as f:
        for tag, d in recs:
            f.write(struct.pack('<II', tag, len(d)) + d)


def client_kinds(path):
    d = open(path, 'rb').read() if os.path.exists(path) else b''
    kinds, o = [], 0
    while o + 4 <= len(d):
        n = struct.unpack('>H', d[o + 2:o + 4])[0]
        if n < 4 or o + n > len(d):
            break
        p = R.decode_packet(d[o:o + n])
        kinds += [q.kind for q in (p.parts if p.kind == 'multi' else [p])]
        o += n
    return kinds


def main():
    if len(sys.argv) != 2 or not os.path.exists(os.path.join(sys.argv[1], 'ntrdpc.exe')):
        sys.exit('usage: winetest.py DIR (DIR holds ntrdpc.exe)')
    d = os.path.abspath(sys.argv[1])
    if not os.path.exists(os.path.join(HERE, 'headless')):
        sys.exit('winetest: build test/headless first: make -C test')
    for f in ('session.rec', 'client.bin', 'relay.log', 'playback.log'):
        if os.path.exists(os.path.join(d, f)):
            os.remove(os.path.join(d, f))
    record(os.path.join(d, 'session.rec'))
    with open(os.path.join(HERE, 'playback.pl'), 'rb') as f, \
            open(os.path.join(d, 'playback.pl'), 'wb') as g:
        g.write(f.read())
    script = (
        'wine reg add "HKCU\\\\Software\\\\Wine\\\\Drivers" /v Graphics /d null /f >/dev/null 2>&1\n'
        'wine reg add "HKCU\\\\Software\\\\Wine\\\\Debug" /v RelayInclude /d "%s" /f'
        ' >/dev/null 2>&1\n'
        'perl playback.pl session.rec 3389 client.bin > playback.log 2>&1 &\n'
        'sleep 1\n'
        'WINEDEBUG=err+all,fixme-all,+relay timeout 25 wine ntrdpc.exe 127.0.0.1:3389'
        ' > relay.log 2>&1\n'
        'sleep 1\n' % RELAY)
    subprocess.run([NT31, 'sh', '-c', script], cwd=d, timeout=180,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(open(os.path.join(d, 'playback.log')).read().replace('\r', '').rstrip())
    relay = open(os.path.join(d, 'relay.log'), 'rb').read().decode('latin-1').replace('\r', '')
    kinds = client_kinds(os.path.join(d, 'client.bin'))
    checks = [
        ('the client sent ' + ' '.join(EXPECT), kinds[:len(EXPECT)] == EXPECT),
        ('the window painted 192 lines',
         'SetDIBitsToDevice() retval=000000c0' in relay),
        ('the pointer became a cursor',
         re.search(r'CreateCursor\(\) retval=0*[1-9a-f]', relay) is not None),
        ('the dialog said "The server closed the connection."',
         '"The server closed the connection."' in relay),
        ('no crash', 'Unhandled' not in relay and 'page fault' not in relay),
    ]
    print('client packets:', ' '.join(kinds))
    for text, ok in checks:
        print('%s  %s' % ('ok  ' if ok else 'FAIL', text))
    ok = all(c[1] for c in checks)
    print('PASS' if ok else 'FAIL')
    sys.exit(0 if ok else 1)


main()
