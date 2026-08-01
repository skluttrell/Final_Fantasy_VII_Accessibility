#!/usr/bin/env python3
"""
ff7_kernel2_sig_ranges.py -- vanilla first_off values for the magic and
command name sections (2026-08-01).

WHY: under 7th Heaven text mods the magic head "Cure|Cure2|" (and on
this log, "Attack|Magic|") no longer match, so v2.30.47 adds fallback
single-entry signatures ("Cure|", "Attack|"). Those weaker rungs get a
plausibility band on the section's u16[base] (= offset of entry 0 =
2 x entry count) so a stray "Attack" string inside e.g. battle text
cannot masquerade as the command section. The bands must bracket the
REAL vanilla values -- this script reads them from kernel2.bin on disk
(LZS-decompressed, the runtime-text ground truth per v2.30.28).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_sig_ranges_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\kernel\kernel2.bin",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\lang-en\kernel\kernel2.bin",
]
path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not path:
    print("ERROR: kernel2.bin not found")
    sys.exit(1)
print(f"Reading: {path}")
raw = open(path, 'rb').read()

def lzs_decompress(src):
    out = bytearray(); win = bytearray(4096); wpos = 0xFEE
    i, n = 0, len(src)
    while i < n:
        ctrl = src[i]; i += 1
        for bit in range(8):
            if i >= n: break
            if ctrl & (1 << bit):
                b = src[i]; i += 1
                out.append(b); win[wpos] = b; wpos = (wpos + 1) & 0xFFF
            else:
                if i + 1 >= n: i = n; break
                b1, b2 = src[i], src[i + 1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4); length = (b2 & 0x0F) + 3
                for k in range(length):
                    b = win[(pos + k) & 0xFFF]
                    out.append(b); win[wpos] = b; wpos = (wpos + 1) & 0xFFF
    return bytes(out)

# kernel2.bin: u32 decompressed size, then LZS stream.
dec = lzs_decompress(raw[4:])
print(f"decompressed: {len(dec):,} bytes")

def enc(ascii_s):
    return bytes((0xFF if c == '|' else ord(c) - 0x20) for c in ascii_s)

# For each signature: find matches, walk backward for the offset-table
# base exactly like the mod's FindSectionBase, report first_off.
for label, sig in (("command 'Attack|Magic|'", enc("Attack|Magic|")),
                   ("magic   'Cure|Cure2|'",   enc("Cure|Cure2|")),
                   ("item    'Potion|Hi-Potion|'", enc("Potion|Hi-Potion|")),
                   ("bare    'Attack|'",       enc("Attack|")),
                   ("bare    'Cure|'",         enc("Cure|"))):
    hits = []
    start = 0
    while True:
        p = dec.find(sig, start)
        if p < 0:
            break
        base = None
        for back in range(2, 0x801, 2):
            if back > p:
                break
            first_off = struct.unpack_from('<H', dec, p - back)[0]
            if first_off == back:
                base = p - back
                break
        hits.append((p, base,
                     struct.unpack_from('<H', dec, base)[0] if base is not None else None))
        start = p + 1
    print(f"\n{label}: {len(hits)} match(es)")
    for p, base, first_off in hits[:8]:
        if base is not None:
            print(f"  match at +0x{p:X}: section base +0x{base:X}, "
                  f"first_off=0x{first_off:X} ({first_off // 2} entries)")
        else:
            print(f"  match at +0x{p:X}: NO self-validating base within 0x800")
