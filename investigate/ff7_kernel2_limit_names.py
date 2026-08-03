#!/usr/bin/env python3
"""
ff7_kernel2_limit_names.py -- what is REALLY stored at magic entries 128+
=========================================================================

WHY (2026-08-03): first-ever limit break in a play-test spoke junk:
  [15:37:03] BATTLE cmd=0x14 named => Cloud, % Y-c'  sSd p vge tex <?>
(2013 install via 7th Heaven, session log.) ResolveActionName branch 7
(cmd 0x14 = Limit) does SectionEntryText(k2_magic, idx + 128) -- a
static-era derivation ("magic entries 128+ hold limit names, 'Braver'...")
that was NEVER live-verified: the 2026-07-11 verification set was
Ice / Potion / Machine Gun / Tentacle, all other branches.

Everything else in the same battle decoded correctly (Ice, Bolt, enemy
attack names, msig='Cure|Cure2|' primary match), so the magic section
itself is fine for entries < 128. Two candidate explanations, decided
by DATA, not theory:

 A. The mod's decoder is wrong for the limit region: FF7Text::Decode
    treats 0xF9 as a single-byte button token (correct for FIELD dialog,
    play-verified) -- but in KERNEL text 0xF9 is the compression token
    (arg byte: length = (arg>>6)*2+4, source offset back = arg & 0x3F,
    per cebix/ff7tools). If vanilla limit entries contain F9 tokens,
    the junk reproduces on VANILLA installs too and the fix is an
    F9-aware decode for kernel sections.

 B. The magic-section-128 derivation itself is wrong (the game may use
    a separate limit text source at runtime, like the summon-attack
    name file) or the 7H profile's kernel simply differs there.

This script decompresses kernel2.bin ON DISK (vanilla ground truth,
2013 install path first), locates the magic-name section by the same
'Cure|Cure2|' head + offset-table backwalk the mod uses, then dumps
entries 125..145: raw bytes, the mod's naive decode, and an F9-aware
decode. If the F9-aware column reads "Braver / Cross-slash / ..."
while the naive column reproduces junk-shaped text, explanation A is
proven offline before any fix is written.

Output tees to a timestamped log next to this script.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_limit_names_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\kernel\kernel2.bin",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\lang-en\kernel\kernel2.bin",
]
path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not path:
    print("ERROR: kernel2.bin not found at either install")
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

dec = lzs_decompress(raw[4:])
print(f"decompressed: {len(dec):,} bytes")

def enc(s):
    return bytes((0xFF if c == '|' else ord(c) - 0x20) for c in s)

# Locate the magic section exactly like the mod: find the 'Cure|Cure2|'
# head, then walk backward to a plausible section base whose u16 offset
# table points at that string as entry 0.
sig = enc("Cure|Cure2|")
hit = dec.find(sig)
if hit < 0:
    print("ERROR: 'Cure|Cure2|' not found in decompressed kernel2")
    sys.exit(1)
base = None
for back in range(2, 0x2400, 2):
    b = hit - back
    if b < 0: break
    first_off = struct.unpack_from('<H', dec, b)[0]
    if first_off == back:           # entry-0 offset lands exactly on the sig
        base = b
        break
if base is None:
    print("ERROR: could not backwalk to section base")
    sys.exit(1)
first_off = struct.unpack_from('<H', dec, base)[0]
count = first_off // 2
print(f"magic section base=+0x{base:X} first_off=0x{first_off:X} implied entries={count}")

# --- the mod's decode (FF7Text::Decode equivalent, kernel-relevant subset):
# 0x00..0x5F -> ASCII (+0x20); 0xFF terminator; leading F8+param skipped by
# SectionEntryText; 0xF6-0xF9 treated as SINGLE-byte tokens (dropped).
def decode_naive(buf, off):
    txt = []
    i = off
    if buf[i] == 0xF8: i += 2         # SectionEntryText's leading-color skip
    while i < len(buf):
        b = buf[i]
        if b == 0xFF: break
        if 0xF6 <= b <= 0xF9:         # mod: single-byte token, emits nothing
            i += 1; continue
        if b <= 0x5F: txt.append(chr(b + 0x20))
        else: txt.append('?')
        i += 1
    return ''.join(txt)

# --- F9-aware decode (kernel-text compression per cebix/ff7tools):
# 0xF9 arg: copy ((arg>>6)*2 + 4) bytes from (position of the F9 byte)
# minus (arg & 0x3F) minus 3, i.e. a lookback into the SECTION byte
# stream; copied bytes are then decoded as normal characters.
def decode_f9(buf, off):
    out_bytes = bytearray()
    def emit_from(i, depth=0):
        if depth > 4: return
        while i < len(buf):
            b = buf[i]
            if b == 0xFF: return
            if b == 0xF9:
                arg = buf[i+1]
                length = ((arg >> 6) * 2) + 4
                src = i - (arg & 0x3F) - 3
                for k in range(length):
                    sb = buf[src + k]
                    if sb == 0xF9:
                        pass          # nested token in source: rare, skip
                    else:
                        out_bytes.append(sb)
                i += 2; continue
            if b == 0xF8:
                i += 2; continue      # color code + param
            out_bytes.append(b); i += 1
    emit_from(off)
    txt = []
    for b in out_bytes:
        if b <= 0x5F: txt.append(chr(b + 0x20))
        elif 0xF6 <= b <= 0xF7: pass
        else: txt.append('?')
    return ''.join(txt)

print("\nidx | raw bytes (first 24)               | naive decode        | F9-aware decode")
print("----+------------------------------------+---------------------+----------------")
for idx in range(120, 150):
    if idx >= count:
        print(f"{idx:3} | (past entry count {count})")
        break
    off = struct.unpack_from('<H', dec, base + idx*2)[0]
    absoff = base + off
    rawb = dec[absoff:absoff+24]
    hexs = ' '.join(f"{b:02X}" for b in rawb)
    print(f"{idx:3} | {hexs:<34} | {decode_naive(dec, absoff):<19} | {decode_f9(dec, absoff)}")
print("\nF9 token census in the whole magic section's string area:")
str_start = base + first_off
str_end   = base + max(struct.unpack_from('<H', dec, base + i*2)[0] for i in range(count)) + 32
f9s = sum(1 for b in dec[str_start:str_end] if b == 0xF9)
print(f"  0xF9 bytes between +0x{str_start-base:X} and +0x{str_end-base:X}: {f9s}")
