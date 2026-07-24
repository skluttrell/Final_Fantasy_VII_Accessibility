#!/usr/bin/env python3
"""
ff7_walkmesh_max_tris.py -- Game-wide maximum walkmesh triangle count
(2026-07-23, triangle-lock bitfield capacity check).

WHY: v2.30.21 reads the IDLCK lock bitfield at 0xCC0E3A (=
modules_global_object + 0xB2). The struct's documented span (≈0x138 bytes,
PSX-decomp-derived) leaves roughly 0x86 bytes of bitfield room = ~1072
triangles. is_triangle_locked() bounds its reads at FWMESH_MAX_TRIS (4096,
a corruption guard) -- if any real field exceeded ~1072 triangles, lock
reads for its high triangles would fall past the struct into neighboring
statics. This script parses every field in flevel.lgp (same walkmesh
parser as the v2.22 dry run) and reports the true game-wide maximum, so
the docs can state the bitfield capacity question with numbers instead of
guesses.

Reuses the lzs/section parsing approach of ff7_walkmesh_route_dryrun.py.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"walkmesh_max_tris_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore)
print(f"Output saving to: {_log_path}\n")

FLEVEL = (r"C:\Program Files (x86)\Steam\steamapps\common"
          r"\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp")

print(f"Reading: {FLEVEL}")
with open(FLEVEL, 'rb') as f:
    data = f.read()
print(f"  {len(data):,} bytes\n")

def lzs_decompress(src, max_out):
    out = bytearray()
    pos = 0
    n = len(src)
    while pos < n and len(out) < max_out:
        flags = src[pos]; pos += 1
        for bit in range(8):
            if pos >= n or len(out) >= max_out:
                break
            if flags & (1 << bit):
                out.append(src[pos]); pos += 1
            else:
                if pos + 1 >= n:
                    break
                b1, b2 = src[pos], src[pos + 1]; pos += 2
                ref = ((b2 & 0xF0) << 4) | b1
                length = (b2 & 0x0F) + 3
                # LZS reference is into a 4096-byte ring aligned to output+18
                start = len(out) - ((len(out) - 18 - ref) & 0xFFF)
                for k in range(length):
                    p = start + k
                    out.append(out[p] if 0 <= p < len(out) else 0)
    return bytes(out)

# LGP TOC
ntoc = struct.unpack_from('<I', data, 12)[0]
entries = []
for i in range(ntoc):
    off = 16 + i * 27
    name = data[off:off+20].split(b'\0')[0].decode('ascii', 'replace')
    fofs = struct.unpack_from('<I', data, off + 20)[0]
    entries.append((name, fofs))
print(f"TOC: {ntoc} files\n")

WALKMESH_IDX = 4
MAX_TRIS = 4096
TRI_SIZE, ACC_SIZE = 24, 6

results = []
for name, fofs in entries:
    try:
        dlen = struct.unpack_from('<I', data, fofs + 20)[0]
        body = data[fofs + 24 : fofs + 24 + dlen]
        comp_len = struct.unpack_from('<I', body, 0)[0]
        dec = lzs_decompress(body[4:4 + comp_len], 4 * 1024 * 1024)
        if len(dec) < 6 + 9 * 4:
            continue
        nsec = struct.unpack_from('<I', dec, 2)[0] if False else 9
        offs = struct.unpack_from('<9I', dec, 6)
        wm_off = offs[WALKMESH_IDX]
        if wm_off == 0 or wm_off + 8 > len(dec):
            continue
        sec_size, ntris = struct.unpack_from('<II', dec, wm_off)
        if ntris == 0 or ntris > MAX_TRIS:
            continue
        need = 4 + ntris * (TRI_SIZE + ACC_SIZE)
        if need > sec_size:
            continue
        results.append((ntris, name))
    except Exception:
        continue

results.sort(reverse=True)
print(f"fields parsed: {len(results)}")
print(f"\nTop 15 by triangle count:")
for ntris, name in results[:15]:
    print(f"  {ntris:5d}  {name}")
if results:
    mx = results[0][0]
    print(f"\nGAME-WIDE MAX: {mx} triangles"
          f" -> lock bitfield needs {(mx + 7) // 8} bytes"
          f" (0xB2 + {((mx + 7) // 8):#x} = struct offset "
          f"{0xB2 + (mx + 7) // 8:#x})")
    print(f"Struct span claim (~0x138): bitfield room = 0x138-0xB2 = 0x86"
          f" bytes = {0x86 * 8} triangles")
    print("VERDICT:", "FITS -- every real field's locks live inside the struct"
          if (mx + 7) // 8 <= 0x86 else
          "EXCEEDS the documented span -- struct is bigger than the PSX "
          "estimate, or high-triangle locks are impossible; check which")
