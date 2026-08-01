#!/usr/bin/env python3
"""
ff7_sttim_wspcl_scan.py -- which fields start a countdown, and what clock
window do they create? (2026-08-01, timer-on-load investigation)

WHY: a save loaded MID-COUNTDOWN keeps ticking, but the mod suppresses it
because no STTIM fired this run (v2.30.8 guard against a STALE value that
also ticks). The engine has NO "timer active" flag -- the decrement at
0x40AC3C is unconditional -- so the only honest discriminator is whether
the CLOCK WINDOW is on screen. WSPCL (0x36) creates it:
    WSPCL win_id, type, x, y   (handler 0x61FD5C: type -> byte
    [0xCFF5D3 + win*0x30], x/y -> words +0xE0/+0xE2)
This scan reports every STTIM (0x38) and WSPCL (0x36) in the game with
their operands, so the clock's TYPE value and typical window id come from
the game's own scripts instead of a guess.
"""
import sys, os, struct, datetime
from collections import defaultdict

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"sttim_wspcl_scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore_stdout():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore_stdout)
print(f"Output saving to: {_log_path}\n")

OPLEN = [
    0, 2, 2, 2, 2, 2, 2, 1, 1, 14, 5, 5, -1, -1, 1, 0,
    1, 2, 1, 2, 5, 6, 7, 8, 7, 8, -1, -1, -1, -1, -1, -1,
    10, 1, 4, 2, 2, 8, 1, 1, 0, 0, 1, 1, 4, 6, 1, 9,
    3, 3, 3, 1, 1, 3, 4, 7, 5, 5, 5, 3, 0, 0, 0, 0,
    2, 4, 5, 1, -1, 4, -1, 4, 6, 3, 1, 1, -1, 4, -1, 4,
    9, 5, 3, 1, 1, 2, 6, 6, 4, 4, 4, 6, 7, 9, 7, 0,
    9, 1, 4, 5, 5, 0, 8, 0, 8, 1, 6, 8, 0, 3, 2, 5,
    3, 1, 2, 3, 3, 7, 3, 4, 3, 4, 2, 2, 2, 2, 1, 2,
    3, 4, 3, 3, 3, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,
    4, 3, 4, 3, 4, 2, 2, 2, 2, 2, 3, 4, 5, 6, 6, 10,
    1, 1, 2, 2, 1, 10, 8, 8, 5, 5, 1, 3, 0, 5, 2, 2,
    4, 4, 3, 2, 5, 5, 1, 3, 4, 3, 2, 4, 4, 3, -1, 1,
    10, 7, 14, 11, 0, 2, 2, 1, 1, 1, 3, 2, 2, 2, 1, 1,
    12, 1, 1, 15, 9, 9, 3, 3, 2, 0, 14, 1, 3, 0, 0, 10,
    3, 3, 2, 2, 2, 4, 4, 4, 6, 9, 9, 4, 4, 7, 7, 10,
    1, 4, 13, 1, 1, 1, 1, 3, 1, 0, 2, 1, 1, 5, 2, 0,
]
SPECIAL_LEN = {0xF5: 1, 0xF6: 4, 0xF7: 2, 0xF8: 2, 0xF9: 0, 0xFA: 0,
               0xFB: 1, 0xFC: 1, 0xFD: 2, 0xFE: 0, 0xFF: 0}
OP_WSPCL, OP_STTIM, OP_WSIZE = 0x36, 0x38, 0x50

def instr_size(code, off):
    op = code[off]
    ln = OPLEN[op]
    if ln < 0: return None
    if op == 0x0F:
        sub = code[off + 1] if off + 1 < len(code) else None
        return SPECIAL_LEN[sub] + 2 if sub in SPECIAL_LEN else None
    if op == 0x28:
        sz = code[off + 1] if off + 1 < len(code) else 0
        return sz if sz >= 3 else None
    return ln + 1

CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp = next((c for c in CANDIDATES if os.path.isfile(c)), None)
data = open(lgp, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = []
for i in range(n_files):
    off = 16 + i * 27
    nm = data[off:off + 20].split(b'\0')[0].decode('ascii', 'replace').lower()
    toc.append((nm, struct.unpack_from('<I', data, off + 20)[0]))

def lzs(src, cap):
    out = bytearray(); win = bytearray(4096); wp = 0xFEE
    i, n = 0, len(src)
    while i < n and len(out) < cap:
        ctrl = src[i]; i += 1
        for b in range(8):
            if len(out) >= cap or i >= n: break
            if ctrl & (1 << b):
                v = src[i]; i += 1
                out.append(v); win[wp] = v; wp = (wp + 1) & 0xFFF
            else:
                if i + 1 >= n: i = n; break
                b1, b2 = src[i], src[i+1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4); ln = (b2 & 0x0F) + 3
                for k in range(ln):
                    v = win[(pos + k) & 0xFFF]
                    out.append(v); win[wp] = v; wp = (wp + 1) & 0xFFF
                    if len(out) >= cap: break
    return bytes(out)

sttim_fields = {}
wspcl_all = defaultdict(list)
for fname, entry in toc:
    flen = struct.unpack_from('<I', data, entry + 20)[0]
    raw = data[entry + 24:entry + 24 + flen]
    if len(raw) < 8: continue
    dec = lzs(raw[4:], 4 * 1024 * 1024)
    if len(dec) < 46: continue
    so = struct.unpack_from('<9I', dec, 6)
    if so[0] != 0x2A or any(so[i] >= so[i+1] for i in range(8)): continue
    sc = so[0] + 4
    if sc + 0x20 > len(dec): continue
    n_ent = dec[sc + 2]
    wstr = struct.unpack_from('<H', dec, sc + 4)[0]
    n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
    tab = 0x20 + n_ent * 8 + n_akao * 4
    if wstr <= tab or sc + wstr > len(dec): continue
    code = dec[sc:sc + wstr]
    # linear-ish sweep over the code block, restarting past bad bytes
    off = tab
    while off < len(code):
        sz = instr_size(code, off)
        if sz is None or off + sz > len(code):
            off += 1
            continue
        op = code[off]
        if op == OP_STTIM and off + 5 <= len(code):
            sttim_fields.setdefault(fname, []).append(
                tuple(code[off+1:off+6]))
        elif op == OP_WSPCL and off + 5 <= len(code):
            wspcl_all[fname].append(tuple(code[off+1:off+5]))
        off += sz

print(f"fields with STTIM (countdown start): {len(sttim_fields)}")
for f, calls in sorted(sttim_fields.items()):
    print(f"  {f}: {calls}")
    if f in wspcl_all:
        print(f"      WSPCL in same field: {wspcl_all[f]}")

print(f"\nfields with WSPCL (special windows): {len(wspcl_all)}")
types = defaultdict(int)
for f, calls in wspcl_all.items():
    for c in calls:
        types[c[1]] += 1
print("WSPCL type-byte histogram (arg2 = the window TYPE):")
for t, n in sorted(types.items()):
    print(f"  type {t}: {n} call(s)")
print("\nWSPCL calls in STTIM fields are the CLOCK windows; the type value")
print("shared by those is what the mod should look for at")
print("[0xCFF5D3 + win*0x30] to know a countdown clock is on screen.")
