"""crosscheck.py - draws random updates with ntrdpc's core and with the
reference renderer of ntrdps (tools/rdpcheck), and compares every pixel.

    make -C test
    python3 -I test/crosscheck.py [CASES] [PACKETS]
    python3 -I test/crosscheck.py --export FILE [CASES] [PACKETS]

CASES (default 10) seeds, each at 8, 15, 16 and 24 bpp; PACKETS (default 12)
updates per case: bitmap tiles (raw, RLE, RLE without header) and drawing
orders (all ten, the caches, bounds), some cases MPPC compressed (8K, 64K,
both expansion modes). The ntrdps folder: ../NTRDPS next to this project,
or the environment variable NTRDPS.
--export writes the cases and the right pictures into FILE instead, for
"replay -m FILE" on NT (nmake replay.exe): it checks the core as each NT
compiler built it.
"""
import array
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NTRDPS = os.environ.get('NTRDPS') or os.path.join(HERE, '..', '..', 'NTRDPS')
sys.path.insert(0, os.path.join(NTRDPS, 'tools', 'rdpcheck'))
sys.path.insert(0, os.path.join(NTRDPS, 'tools', 'specmodels', 'mppc'))
import rdpcheck as R      # noqa: E402
import mppc_model as M    # noqa: E402
ORD, RLE, BD = R.ORD, R.RLE, R.BD

REPLAY = os.path.join(HERE, 'replay')
W, H = 96, 64
GCELL = [4, 4, 8, 8, 16, 32, 64, 128, 256, 2048]
BCELL = [256, 1024, 4096]
ENC = None                  # the MPPC encoder of the case, or None
STATS = {}


def sdin(t2, body):
    """A Share Data PDU from the server, MPPC compressed when ENC is set."""
    if ENC is None:
        return BD.wrap_sdin(BD.share_data(t2, BD.Msg('body').add(body, ''), R.FIRST_SHARE),
                            None).data()
    flags, payload = ENC.compress(body)
    STATS[flags & 0xE0] = STATS.get(flags & 0xE0, 0) + 1
    total = 18 + len(payload)
    sd = struct.pack('<HHHIBBHBBH', total, 0x17, 1002, R.FIRST_SHARE, 0, 2, 18 + len(body), t2,
                     flags, total if flags & 0x20 else 0) + payload
    return BD.wrap_sdin(BD.Msg('x').add(sd, ''), None).data()


def tsc(v, bpp):
    if bpp == 8:
        return (v & 0xFF, 0, 0)
    if bpp in (15, 16):
        return (v & 0xFF, v >> 8 & 0xFF, 0)
    return (v >> 16 & 0xFF, v >> 8 & 0xFF, v & 0xFF)


def pixbytes(vals, bpp):
    nb = (bpp + 7) // 8
    return b''.join(v.to_bytes(nb, 'little') for v in vals)


class Gen:
    def __init__(self, rng, bpp):
        self.rng, self.bpp = rng, bpp
        self.enc = ORD.Encoder()
        self.mask = R.PIXEL_MASK[bpp]
        self.ctab = False
        self.gslot = 0

    def px(self):
        return self.rng.randrange(self.mask + 1)

    def col(self):
        return tsc(self.px(), self.bpp)

    def rect(self, mw=W, mh=H):
        r = self.rng
        x, y = r.randrange(W), r.randrange(H)
        return x, y, r.randrange(1, min(mw, W - x) + 1), r.randrange(1, min(mh, H - y) + 1)

    def bounds(self):
        r = self.rng
        if r.random() < 0.3:
            l, t = r.randrange(W), r.randrange(H)
            return (l, t, r.randrange(l, W), r.randrange(t, H))
        return None

    def opaque(self):
        x, y, w, h = self.rect()
        c = self.col()
        return [self.enc.encode(ORD.OPAQUERECT, dict(left=x, top=y, width=w, height=h, c0=c[0],
                                                     c1=c[1], c2=c[2]), self.bounds())]

    def multi(self):
        r = self.rng
        x, y, w, h = self.rect()
        n = r.randrange(1, 6)
        rects = []
        for _ in range(n):
            rx, ry = r.randrange(x, x + w), r.randrange(y, y + h)
            rects.append((rx, ry, r.randrange(1, x + w - rx + 1), r.randrange(1, y + h - ry + 1)))
        c = self.col()
        return [self.enc.encode(ORD.MULTIOPAQUERECT, dict(
            left=x, top=y, width=w, height=h, c0=c[0], c1=c[1], c2=c[2], n=n,
            rects=ORD.enc_delta_rects(rects)), self.bounds())]

    def patblt(self):
        r = self.rng
        x, y, w, h = self.rect()
        rop = r.choice([v for v in range(256) if not R.rop_uses(v)[1] and v != 0x5F])
        style = r.choice([0, 3])
        f = dict(left=x, top=y, width=w, height=h, rop=rop, back=self.col(), fore=self.col(),
                 orgx=r.randrange(8), orgy=r.randrange(8), style=style,
                 hatch=r.randrange(256) if style == 3 else 0,
                 extra=bytes(r.randrange(256) for _ in range(7)) if style == 3 else bytes(7))
        return [self.enc.encode(ORD.PATBLT, f, self.bounds())]

    def dstblt(self):
        x, y, w, h = self.rect()
        return [self.enc.encode(ORD.DSTBLT, dict(left=x, top=y, width=w, height=h,
                                                 rop=self.rng.choice([0, 0x55, 0xAA, 0xFF])),
                                self.bounds())]

    def scrblt(self):
        r = self.rng
        x, y, w, h = self.rect()
        rop = r.choice([0xCC] * 4 + [v for v in range(256) if not R.rop_uses(v)[0]])
        return [self.enc.encode(ORD.SCRBLT, dict(left=x, top=y, width=w, height=h, rop=rop,
                                                 xsrc=r.randrange(W - w + 1),
                                                 ysrc=r.randrange(H - h + 1)), self.bounds())]

    def lineto(self):
        r = self.rng
        return [self.enc.encode(ORD.LINETO, dict(
            backmode=1, xs=r.randrange(W), ys=r.randrange(H), xe=r.randrange(W),
            ye=r.randrange(H), back=self.col(), rop2=r.randrange(1, 17), penstyle=0, penwidth=1,
            pencolor=self.col()), self.bounds())]

    def memblt(self):
        r = self.rng
        out = []
        if self.bpp == 8 and not self.ctab:
            out.append(ORD.secondary(1, 0, struct.pack('<BH', 0, 256) +
                                     b''.join(bytes((i, i, i, 0)) for i in range(256))))
            self.ctab = True
        cid = r.randrange(3)
        nb = (self.bpp + 7) // 8
        bw = 4 * r.randrange(1, 9)
        bh = r.randrange(1, min(255, BCELL[cid] // bw) + 1)
        slot = r.randrange(8)
        pix = self.picture(bw, bh)
        if r.random() < 0.4:
            t, extra, data = 0, 0, pixbytes(pix, self.bpp)
        else:
            t, extra, data = 2, 0x0400, RLE.encode(pix, bw, bh, self.bpp)
        out.append(ORD.secondary(t, extra, struct.pack('<BBBBBHH', cid, 0, bw, bh, self.bpp,
                                                       len(data), slot) + data))
        w, h = r.randrange(1, bw + 1), r.randrange(1, bh + 1)
        x, y = r.randrange(W - w + 1) if w <= W else 0, r.randrange(H - h + 1) if h <= H else 0
        if w > W or h > H:
            return out
        rop = 0xCC if self.bpp == 8 or r.random() < 0.6 else r.choice(
            [v for v in range(256) if not R.rop_uses(v)[0]])
        out.append(self.enc.encode(ORD.MEMBLT, dict(
            cacheid=cid, left=x, top=y, width=w, height=h, rop=rop, xsrc=r.randrange(bw - w + 1),
            ysrc=r.randrange(bh - h + 1), cacheindex=slot), self.bounds()))
        return out

    def savebmp(self):
        r = self.rng
        x, y, w, h = self.rect(40, 40)
        pos = 20 * r.randrange(100)
        f = dict(pos=pos, left=x, top=y, right=x + w - 1, bottom=y + h - 1)
        out = [self.enc.encode(ORD.SAVEBITMAP, dict(f, op=0))]
        out += self.opaque() + self.patblt()
        out.append(self.enc.encode(ORD.SAVEBITMAP, dict(f, op=1)))
        return out

    def text(self):
        r = self.rng
        cid = r.randrange(10)
        cell = GCELL[cid]
        n = r.randrange(1, 5)
        glyphs = []
        for i in range(n):
            while True:
                cx, cy = r.randrange(1, 25), r.randrange(1, 25)
                if (((cx + 7) // 8) * cy + 3) & ~3 <= cell:
                    break
            slot = (self.gslot + i) % (250 if cid < 9 else 64)
            gx, gy = r.randrange(-3, 4), r.randrange(-cy - 2, 2)
            bits = bytes(r.randrange(256) for _ in range(((cx + 7) // 8) * cy))
            size = (len(bits) + 3) & ~3
            glyphs.append((slot, gx, gy, cx, cy, bits.ljust(size, b'\0')))
        self.gslot = (self.gslot + n) % 250
        out = [ORD.secondary(3, 0, struct.pack('<BB', cid, n) + b''.join(
            struct.pack('<HhhHH', s, gx, gy, cx, cy) + b for s, gx, gy, cx, cy, b in glyphs))]
        # placement: advances, then the cells must sit on screen and inside Bk
        advs = [r.randrange(0, 20) for _ in glyphs]
        for _ in range(50):
            ox, oy = r.randrange(W), r.randrange(H)
            cells, x = [], ox
            for (s, gx, gy, cx, cy, b), a in zip(glyphs, advs):
                x += a
                cells.append((x + gx, oy + gy, x + gx + cx, oy + gy + cy))
            l = min(c[0] for c in cells)
            t = min(c[1] for c in cells)
            rr = max(c[2] for c in cells)
            bb = max(c[3] for c in cells)
            if l >= 0 and t >= 0 and rr <= W and bb <= H:
                break
        else:
            return out
        data = b''
        for (s, gx, gy, cx, cy, b), a in zip(glyphs, advs):
            data += bytes([s]) + (bytes([a]) if r.random() < 0.8 else b'\x80' + struct.pack('<H', a))
        bk = (max(0, l - r.randrange(3)), max(0, t - r.randrange(3)),
              min(W, rr + r.randrange(3)), min(H, bb + r.randrange(3)))
        kind = r.randrange(3)
        if kind == 0:
            op = (0, 0, 0, 0)
        else:
            op = bk
        text, opaque = self.col(), self.col()
        if r.random() < 0.5:
            f = dict(cacheid=cid, fdrawing=0x0200, back=text, fore=opaque, bkl=bk[0], bkt=bk[1],
                     bkr=bk[2], bkb=bk[3], opl=op[0], opt=op[1], opr=op[2], opb=op[3], x=ox,
                     y=oy, data=data)
            if kind == 2:
                f.update(opl=0, opt=0x0F, opr=0, opb=-32768 & 0xFFFF)
            if kind != 0 and (op[0] == 0 and bk[0] != 0 or op[2] == 0 and bk[2] != 0):
                return out
            if ox == bk[0] and r.random() < 0.5:
                f['x'] = 0x8000
            out.append(self.enc.encode(ORD.FASTINDEX, f, self.bounds()))
        else:
            f = dict(cacheid=cid, flaccel=2, charinc=0, opredundant=0, back=text, fore=opaque,
                     bkl=bk[0], bkt=bk[1], bkr=bk[2], bkb=bk[3], opl=op[0], opt=op[1],
                     opr=op[2], opb=op[3], x=ox, y=oy, data=data)
            out.append(self.enc.encode(ORD.GLYPHINDEX, f, self.bounds()))
        return out

    def picture(self, w, h):
        """Pixels with runs and repeated rows, so RLE uses most of its codes."""
        r = self.rng
        cols = [self.px() for _ in range(4)]
        rows, prev = [], None
        for _ in range(h):
            if prev is not None and r.random() < 0.4:
                row = list(prev)
                for _ in range(r.randrange(3)):
                    row[r.randrange(w)] = r.choice(cols)
            else:
                row = []
                while len(row) < w:
                    k = r.randrange(5)
                    if k == 0:
                        row += [self.px() for _ in range(r.randrange(1, 6))]
                    elif k == 1:
                        a, b = r.choice(cols), r.choice(cols)
                        row += [a, b] * r.randrange(1, 5)
                    else:
                        row += [r.choice(cols)] * r.randrange(1, 12)
                row = row[:w]
            rows.append(row)
            prev = row
        return [v for row in rows for v in row]

    def bitmap(self):
        r = self.rng
        tiles = []
        for _ in range(r.randrange(1, 4)):
            w, h = 4 * r.randrange(1, 9), r.randrange(1, 20)
            x, y = r.randrange(W - w + 1), r.randrange(H - h + 1)
            nb = (self.bpp + 7) // 8
            pix = self.picture(w, h)
            k = r.randrange(3)
            if k == 0:
                flags, data = 0, pixbytes(pix, self.bpp)
            else:
                rle = RLE.encode(pix, w, h, self.bpp)
                if k == 1:
                    flags, data = 0x0001, struct.pack('<4H', 0, len(rle), w * nb, w * h * nb) + rle
                else:
                    flags, data = 0x0401, rle
            tiles.append(struct.pack('<9H', x, y, x + w - 1, y + h - 1, w, h, self.bpp, flags,
                                     len(data)) + data)
        return struct.pack('<HH', 1, len(tiles)) + b''.join(tiles)


KINDS = ['opaque', 'multi', 'patblt', 'dstblt', 'scrblt', 'lineto', 'memblt', 'savebmp', 'text']


def make_case(seed, bpp, npkt):
    """One case: the in.bin bytes for replay, and the picture rdpcheck drew."""
    rng = random.Random(seed * 100 + bpp)
    scr = R.order_screen(W, H, bpp, 'all')
    base = array.array('I', scr.nat)
    g = Gen(rng, bpp)
    pkts = []
    for _ in range(npkt):
        if rng.random() < 0.25:
            body = g.bitmap()
        else:
            orders = []
            for _ in range(rng.randrange(1, 12)):
                orders += getattr(g, rng.choice(KINDS))()
            body = R.orders_update(*orders)
        R.decode_update(body, scr)
        pkts.append(sdin(2, body))
    data = struct.pack('<III', W, H, bpp) + struct.pack('<%dI' % (W * H), *base) + b''.join(pkts)
    return data, list(scr.nat)


def run(seed, bpp, path, npkt):
    data, want = make_case(seed, bpp, npkt)
    with open(path, 'wb') as f:
        f.write(data)
    out = path + '.out'
    p = subprocess.run([REPLAY, path, out], capture_output=True, text=True)
    got = array.array('I')
    with open(out, 'rb') as f:
        got.frombytes(f.read())
    bad = [i for i in range(W * H) if got[i] != want[i]]
    ok = p.returncode == 0 and not bad and not p.stdout.strip()
    if not ok:
        print('seed %d bpp %d: exit %d, %d pixels differ %s %s' % (
            seed, bpp, p.returncode, len(bad),
            [(i % W, i // W, hex(got[i]), hex(want[i])) for i in bad[:6]], p.stdout.strip()))
    return ok


def cases(n):
    """(seed, bpp) of each case; sets ENC, the MPPC encoder of the case."""
    global ENC
    modes = [None] + [(t, m, p) for t in (0, 1) for m in ('rollback', 'reset')
                      for p in (False, True)]
    for seed in range(n):
        for bpp in (8, 15, 16, 24):
            mode = modes[(seed * 4 + bpp) % len(modes)]
            if mode is None:
                ENC = None
            else:
                t, m, perfect = mode
                ENC = (M.PerfectEncoder if perfect else M.Encoder)(t, expansion_mode=m)
            yield seed, bpp


def main():
    args = sys.argv[1:]
    export = None
    if args[:1] == ['--export']:
        if len(args) < 2:
            sys.exit('usage: crosscheck.py --export FILE [CASES] [PACKETS]')
        export, args = args[1], args[2:]
    ncases = int(args[0]) if len(args) > 0 else 10
    npkt = int(args[1]) if len(args) > 1 else 12
    if export:
        with open(export, 'wb') as f:
            for seed, bpp in cases(ncases):
                data, want = make_case(seed, bpp, npkt)
                f.write(struct.pack('<I', len(data)) + data +
                        struct.pack('<%dI' % (W * H), *want))
        print('wrote %d cases to %s (%d bytes); run: replay -m %s' % (
            ncases * 4, export, os.path.getsize(export), os.path.basename(export)))
        return
    if not os.path.exists(REPLAY):
        sys.exit('crosscheck: build test/replay first: make -C test')
    fails = total = 0
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'case.bin')
        for seed, bpp in cases(ncases):
            total += 1
            if not run(seed, bpp, path, npkt):
                fails += 1
    print('%d of %d cases equal; MPPC packets by flags: %s' % (
        total - fails, total, {hex(k): v for k, v in sorted(STATS.items())}))
    sys.exit(1 if fails else 0)


main()
