"""fakeserver.py - runs test/headless against the fake RDP server of ntrdps
(tools/rdpcheck FakeServer) and compares the picture it drew.

    make -C test
    python3 -I test/fakeserver.py [--orders] [headless options]

--orders: the server sends drawing orders too, not only bitmap tiles.
Other options go to headless, e.g. -k (keys and mouse) or -r (refresh).
Exit status 0 = the session became active, the picture is right, and the
server saw no protocol error. The ntrdps folder: ../NTRDPS next to this
project, or the environment variable NTRDPS.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NTRDPS = os.environ.get('NTRDPS') or os.path.join(HERE, '..', '..', 'NTRDPS')
sys.path.insert(0, os.path.join(NTRDPS, 'tools', 'rdpcheck'))
import rdpcheck as R    # noqa: E402

HEADLESS = os.path.join(HERE, 'headless')


def main():
    if not os.path.exists(HEADLESS):
        sys.exit('fakeserver: build test/headless first: make -C test')
    orders = '--orders' in sys.argv
    extra = [a for a in sys.argv[1:] if a != '--orders']
    srv = R.FakeServer(256, 192, None, orders=orders)
    srv.start()
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'screen.ppm')
        p = subprocess.run([HEADLESS, '-s', '3', '-o', out] + extra +
                           ['127.0.0.1', str(srv.port)],
                           capture_output=True, text=True, timeout=30)
        srv.join(10)
        print(p.stdout.rstrip())
        print('server error:', srv.error)
        print('server got:', ' '.join(srv.got))
        print('input events:', srv.events)
        data = open(out, 'rb').read() if os.path.exists(out) else b''
    want = R.test_picture(256, 192)
    rgb = data[data.index(b'255\n') + 4:] if b'255\n' in data else b''
    if len(rgb) != len(want):
        print('picture: %d bytes, expected %d' % (len(rgb), len(want)))
        diffs = -1
    else:
        diffs, first = R.picture_diffs(rgb, want, 256)
        print('picture: %d pixels differ %s' % (diffs, first))
    ok = p.returncode == 0 and srv.error is None and diffs == 0
    print('PASS' if ok else 'FAIL')
    sys.exit(0 if ok else 1)


main()
