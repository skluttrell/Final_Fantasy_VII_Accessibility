#!/usr/bin/env python3
"""
ff7_kernel2_offset_monotonic.py -- is the offset table ALWAYS sorted?
=====================================================================

WHY (2026-08-04): the limit-name junk of 2026-08-03 is now explained as a
STALE-COPY read, not a decode/index bug: the v2.30.76 probe run showed all
limit resolutions correct (sane idx, byte-identical vanilla text on BOTH
installs), while the same two logs each caught a kernel2 section going
stale mid-battle ("head gone" at 0FD4F916 / 0BE69985 -- transient
low-address loading buffers that the first-match address-space walk finds
BEFORE the resident copy). The use-time validator only re-checks the
section HEAD signature, so a stale copy whose first bytes survive while
its BODY is reused passes and decodes garbage -- exactly the reported
junk (Ice/Bolt near the head spoke fine; Braver at +0x657 spoke junk).

PLANNED FIX: extend the use-time check with a body-structure probe --
every u16 in the entry-offset table must be non-decreasing and inside
[table_size, 0x8000]. Randomly reused memory passing an N-point monotone
run is astronomically unlikely, so this closes the head-intact/body-dead
window. BUT the check dead-gates every name if the invariant does not
hold on REAL data (cf. the battle_end!=0 dead-gate lesson, v2.30.75), so
this script proves it offline first, against every section the mod scans
for, in BOTH installs' kernel2.bin.

The FILE stores F9-compressed text and the runtime heap copy is the
F9-expanded rebuild, but both are sequential per-entry re-packs of the
same entry order -- if the file tables are monotone the expanded tables
are too (expansion only grows string lengths in place, order unchanged).
Today's live probes agree (entry 128 off 0x643/0x657 < entry 135 off
0x69F/0x6B3 on the two installs).

Output tees to a timestamped log next to this script.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_offset_monotonic_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    try: _log_file.close()
    except Exception: pass
atexit.register(_restore)
print(f"Output saving to: {_log_path}\n")

INSTALLS = [
    ("2013", r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\lang-en\kernel\kernel2.bin"),
    ("2026", r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\lang-en\kernel\kernel2.bin"),
]

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

def enc(s):
    return bytes((0xFF if c == '|' else ord(c) - 0x20) for c in s)

# The exact signature set ScanKernel2Sections uses (proxy.cpp), including
# the raw-byte accessory-description head (colour codes B2/B3).
ACC_DESC_SIG = bytes([0xB2]) + enc("Strength") + bytes([0xB3]) + enc(" +10")
# Each entry: (name, [sig rungs...], band). Rungs mirror the scanner's
# ladder (v2.30.47): full head first, single-entry fallback banded by the
# section's fixed entry count. The command section NEEDS its fallback here:
# "Attack|Magic|" does not self-validate in the F9-compressed FILE (known
# since v2.30.47) -- only the runtime expansion carries the full head.
SECTIONS = [
    ("magic",          [enc("Cure|Cure2|"), enc("Cure|")], (0x1F0, 0x210)),
    ("item",           [enc("Potion|Hi-Potion|")],         None),
    ("weapon",         [enc("Buster Sword|")],             None),
    ("command",        [enc("Attack|Magic|"), enc("Attack|")], (0x28, 0x40)),
    ("armor",          [enc("Bronze Bangle|")],            None),
    ("accessory",      [enc("Power Wrist|")],              None),
    ("item_desc",      [enc("Restores HP by 100|")],       None),
    ("magic_desc",     [enc("Restores HP|Restores HP|")],  (0x1F0, 0x210)),
    ("materia_name",   [enc("MP Plus|HP Plus|")],          None),
    ("materia_desc",   [enc("Increases MP capacity|")],    None),
    ("weapon_desc",    [enc("Initial equipment|")],        None),
    ("accessory_desc", [ACC_DESC_SIG],                     None),
]

def find_section(dec, sigs, band):
    """Sig-rung ladder + offset-table backwalk, same self-validating rule
    as FindSectionBase; band = optional (min_fo, max_fo) on u16[base]."""
    for sig in sigs:
        start = 0
        while True:
            hit = dec.find(sig, start)
            if hit < 0:
                break              # this rung misses everywhere: next rung
            found = None
            for back in range(2, 0x2400, 2):
                b = hit - back
                if b < 0: break
                first_off = struct.unpack_from('<H', dec, b)[0]
                if first_off == back:
                    if band and not (band[0] <= first_off <= band[1]):
                        break      # right shape, wrong entry count: next hit
                    found = b
                    break
            if found is not None:
                return found
            start = hit + 1
    return None

overall_ok = True
for label, path in INSTALLS:
    if not os.path.isfile(path):
        print(f"[{label}] MISSING: {path}")
        overall_ok = False
        continue
    dec = lzs_decompress(open(path, 'rb').read()[4:])
    print(f"[{label}] {path}")
    print(f"[{label}] decompressed: {len(dec):,} bytes")
    print(f"{'section':<15} | base    | entries | off range       | monotone | in-band")
    print("-" * 78)
    for name, sigs, band in SECTIONS:
        base = find_section(dec, sigs, band)
        if base is None:
            print(f"{name:<15} | NOT FOUND")
            overall_ok = False
            continue
        tab = struct.unpack_from('<H', dec, base)[0]
        count = tab // 2
        offs = [struct.unpack_from('<H', dec, base + i*2)[0] for i in range(count)]
        mono = all(offs[i] <= offs[i+1] for i in range(count - 1))
        band_ok = all(tab <= o <= 0x8000 for o in offs)
        print(f"{name:<15} | +0x{base:04X} | {count:7} | 0x{min(offs):04X}..0x{max(offs):04X} "
              f"| {'YES' if mono else 'NO !!!':<8} | {'YES' if band_ok else 'NO !!!'}")
        if not (mono and band_ok):
            overall_ok = False
            bad = [(i, offs[i], offs[i+1]) for i in range(count-1) if offs[i] > offs[i+1]]
            for i, a, b in bad[:10]:
                print(f"    VIOLATION entry {i}: 0x{a:X} > 0x{b:X}")
    print()

# --- Supplementary hunt: the REAL command section --------------------------
# The sig ladder cannot locate command in the FILE (F9 tokens break both
# rungs; the "Attack|" hit above backwalks to a COINCIDENTAL u16==0x30 in
# text -- its "offsets" are string bytes, which is why it fails the check;
# the planned body check REJECTING it is the check doing its job). Find the
# real table structurally instead: a base whose u16[0]==0x30 (24 entries)
# with all 24 offsets monotone in [0x30, 0x800] and entry 0 decoding to
# "Attack". Existence proves the file's command table obeys the invariant.
print("Structural hunt for the real command table (u16[0]==0x30, 24 monotone offsets):")
for label, path in INSTALLS:
    if not os.path.isfile(path):
        continue
    dec = lzs_decompress(open(path, 'rb').read()[4:])
    found_any = False
    for b in range(0, len(dec) - 0x40, 2):
        fo = struct.unpack_from('<H', dec, b)[0]
        if not (0x28 <= fo <= 0x40) or (fo & 1):
            continue
        n = fo // 2
        offs = [struct.unpack_from('<H', dec, b + i*2)[0] for i in range(n)]
        if not all(fo <= o <= 0x2000 for o in offs):
            continue
        head = dec[b + fo : b + fo + 7]
        txt = ''.join(chr(c + 0x20) if c <= 0x5F else ('|' if c == 0xFF else '?')
                      for c in head)
        if not txt.startswith("Attack"):
            continue
        found_any = True
        mono = all(offs[i] <= offs[i+1] for i in range(n - 1))
        print(f"  [{label}] base=+0x{b:04X} entries={n} monotone={'YES' if mono else 'NO'}")
        print(f"           offs: {' '.join(f'{o:X}' for o in offs)}")
    if not found_any:
        print(f"  [{label}] no in-file command table found at all")

print()
print("VERDICT: see per-section table above -- the 11 sig-locatable sections")
print("decide the ship question; the command hunt covers the 12th.")
