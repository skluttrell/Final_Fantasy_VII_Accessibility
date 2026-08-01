#!/usr/bin/env python3
"""
ff7_kernel2_section_enum.py -- enumerate EVERY kernel2 text section with
its first entries (2026-08-01, magic-menu completion work).

WHY: the magic menu needs SPELL DESCRIPTIONS, and the mod locates kernel2
sections by the head-text signature of entry 0 (never by index). This
walks the decompressed kernel2, finds every self-validating section base
(u16[base] == distance from base to entry 0 -- the same rule
FindSectionBase uses at runtime), and prints each section's entry count
plus its first entries. From that list the magic-description section and
a safe head signature can be read off directly instead of guessed.

Also prints, for each candidate signature, whether it is UNIQUE in the
file -- the property that makes it safe to scan for at runtime.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_section_enum_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\lang-en\kernel\kernel2.bin",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\kernel\kernel2.bin",
]
path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
print(f"Reading: {path}")
raw = open(path, 'rb').read()

def lzs(src):
    out = bytearray(); win = bytearray(4096); wp = 0xFEE
    i, n = 0, len(src)
    while i < n:
        ctrl = src[i]; i += 1
        for b in range(8):
            if i >= n: break
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
    return bytes(out)

dec = lzs(raw[4:])
print(f"decompressed: {len(dec):,} bytes\n")

def decode(off, limit=70):
    out = []
    while off < len(dec) and len(out) < limit:
        c = dec[off]; off += 1
        if c == 0xFF: break
        if c == 0xE7 or c == 0xE0: out.append(' ')
        elif c <= 0xDF: out.append(chr(c + 0x20))
        elif c in (0xE2,): out.append(',')
        else: out.append('~')
    return ''.join(out)

# A section base: u16[base] == distance to entry 0, entry 0 is printable
# text, and the table is plausibly sized.
sections = []
for base in range(0, len(dec) - 2, 2):
    first_off = struct.unpack_from('<H', dec, base)[0]
    if first_off < 2 or first_off > 0x800 or base + first_off >= len(dec):
        continue
    n_entries = first_off // 2
    if n_entries < 4:
        continue
    # entry 0 must decode to something texty
    s0 = decode(base + first_off, 24)
    if len(s0) < 3 or not any(c.isalpha() for c in s0):
        continue
    # sanity: entry 1's offset must also be inside the file and >= first
    o1 = struct.unpack_from('<H', dec, base + 2)[0]
    if o1 < first_off or base + o1 >= len(dec):
        continue
    sections.append((base, n_entries))

# keep the first base of each run (adjacent bases can self-validate)
filtered = []
for base, n in sections:
    if filtered and base - filtered[-1][0] < 0x40:
        continue
    filtered.append((base, n))

print(f"{len(filtered)} candidate sections:\n")
for base, n in filtered:
    ents = []
    for i in range(min(4, n)):
        o = struct.unpack_from('<H', dec, base + i * 2)[0]
        ents.append(decode(base + o, 46))
    print(f"  base +0x{base:04X}  entries={n}")
    for i, e in enumerate(ents):
        print(f"      [{i}] {e!r}")
    print()

# uniqueness check for the signatures the mod uses / might use
def enc(s):
    return bytes((0xFF if c == '|' else ord(c) - 0x20) for c in s)

print("signature uniqueness in kernel2 (count of byte-matches):")
for sig in ("Cure|Cure2|", "Cure|", "Restores HP|", "Restores a little HP|",
            "Potion|Hi-Potion|", "MP Plus|HP Plus|"):
    pat = enc(sig)
    cnt = 0
    start = 0
    while True:
        p = dec.find(pat, start)
        if p < 0: break
        cnt += 1
        start = p + 1
    print(f"  {sig!r}: {cnt}")
