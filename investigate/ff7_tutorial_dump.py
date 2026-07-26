#!/usr/bin/env python3
"""
ff7_tutorial_dump.py -- locate and decode FF7 menu-tutorial scripts
(2026-07-26 play report: the Materia tutorial spoke nothing; its text
never passes the MESSAGE hooks -- tutorials are a separate script system
interpreted by the MENU module).

WHERE TUTORIALS LIVE (community-documented, validated here): the field
script section's header carries nAkaoOffsets u32 offsets (relative to
the SECTION start). Each points to either an AKAO music block (magic
"AKAO") or a TUTORIAL script (no magic). The field TUTOR opcode (0x21,
1-byte arg) plays entry N of that same table.

TUTORIAL SCRIPT FORMAT (empirical -- this script validates it against
mds7pb_2, the hideout field where the Materia tutorial runs):
  u16 window-related? then a byte-code stream:
    0x00..0x0F  control (waits, simulated key presses: 02 up 03 down
                04 right 05 left 06 rotate?, 09 OK, 0A cancel ...)
    0x10        WINDOW: u16 x, u16 y (open a text window)
    0x11        TEXT: FF7-encoded text follows until 0xFF terminator
    0x12        (unknown / wait)
    0xFF        end of script
  (Exact control semantics do not matter for TTS -- only finding 0x11
  text runs does. The parse below is deliberately tolerant: it scans
  for 0x11 and decodes the following FF7 text to the 0xFF terminator,
  which the standard field text table maps cleanly to ASCII.)

Output: every akao-table entry of mds7pb_2 classified (AKAO vs
tutorial), and every text run of every tutorial decoded -- the Materia
tutorial's sentences should read out. Also sweeps ALL fields for
tutorial entries to size the feature (how many fields carry them).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"tutorial_dump_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found")
    sys.exit(1)
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = []
for i in range(n_files):
    off = 16 + i * 27
    nm = data[off:off + 20].split(b'\0')[0].decode('ascii', 'replace').lower()
    toc.append((nm, struct.unpack_from('<I', data, off + 20)[0]))

def lzs_decompress(src, max_out):
    out = bytearray()
    win = bytearray(4096)
    wpos = 0xFEE
    i, n = 0, len(src)
    while i < n and len(out) < max_out:
        ctrl = src[i]; i += 1
        for bit in range(8):
            if len(out) >= max_out or i >= n:
                break
            if ctrl & (1 << bit):
                b = src[i]; i += 1
                out.append(b)
                win[wpos] = b
                wpos = (wpos + 1) & 0xFFF
            else:
                if i + 1 >= n:
                    i = n; break
                b1, b2 = src[i], src[i + 1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4)
                length = (b2 & 0x0F) + 3
                for k in range(length):
                    b = win[(pos + k) & 0xFFF]
                    out.append(b)
                    win[wpos] = b
                    wpos = (wpos + 1) & 0xFFF
                    if len(out) >= max_out:
                        break
    return bytes(out)

# Standard FF7 field text table (the same mapping ff7_text.cpp uses for
# the base ranges -- enough for tutorial prose).
def decode_ff7(bs):
    out = []
    for b in bs:
        if b == 0xFF:
            break
        if 0x00 <= b <= 0x19:
            out.append(chr(ord(' ') + b))          # ' '..'9' block? no --
        else:
            out.append(None)
    return out

# The real base table: 0x00=' ', 0x01='!', ... standard ASCII offset:
# byte 0x00-0x5F maps to ASCII 0x20-0x7F ("<=0x5E is ASCII+0x20" rule
# the mod's decoder uses), 0xD4..: linebreak-ish, 0xE7 newline etc.
def decode_text(bs):
    out = []
    i = 0
    while i < len(bs):
        b = bs[i]
        if b == 0xFF:
            break
        if b <= 0x5E:
            out.append(chr(0x20 + b))
        elif b == 0xE7 or b == 0xE8:
            out.append('\n')                       # newline / page
        elif b == 0xE2:
            out.append(', ')
        elif 0xEA <= b <= 0xF2:
            out.append('{name}')
        else:
            out.append(f'<{b:02X}>')
        i += 1
    return ''.join(out), i

def field_tutorials(fname_want=None):
    results = {}
    for fname, entry_off in toc:
        if fname_want and fname != fname_want:
            continue
        flen = struct.unpack_from('<I', data, entry_off + 20)[0]
        raw = data[entry_off + 24:entry_off + 24 + flen]
        if len(raw) < 8:
            continue
        dec = lzs_decompress(raw[4:], 4 * 1024 * 1024)
        if len(dec) < 42:
            continue
        sec_offs = struct.unpack_from('<9I', dec, 6)
        if sec_offs[0] != 0x2A or any(sec_offs[i] >= sec_offs[i + 1]
                                      for i in range(8)):
            continue
        sc = sec_offs[0] + 4
        sec_end = sec_offs[1]
        n_ent = dec[sc + 2]
        n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
        if n_akao == 0:
            continue
        offs = [struct.unpack_from('<I', dec, sc + 0x20 + n_ent * 8 + a * 4)[0]
                for a in range(n_akao)]
        entries = []
        for a, o in enumerate(offs):
            p = sc + o
            if p + 4 > len(dec) or p >= sec_end:
                entries.append((a, o, 'OOB', None))
                continue
            magic = dec[p:p + 4]
            if magic == b'AKAO':
                entries.append((a, o, 'AKAO', None))
            else:
                # candidate tutorial: scan for 0x11 text runs up to the
                # next entry/section end
                hi = sec_end
                for o2 in offs:
                    if o2 > o and sc + o2 < hi:
                        hi = sc + o2
                texts = []
                q = p
                while q < hi:
                    if dec[q] == 0x11:
                        txt, used = decode_text(dec[q + 1:hi])
                        if len(txt.strip()) >= 2:
                            texts.append(txt)
                        q += 1 + used + 1
                    elif dec[q] == 0xFF:
                        break
                    else:
                        q += 1
                entries.append((a, o, 'TUT', texts))
        if any(k == 'TUT' for _, _, k, _ in entries):
            results[fname] = entries
    return results

print("=== mds7pb_2 (the Materia tutorial field) ===")
r = field_tutorials('mds7pb_2')
for fname, entries in r.items():
    for a, o, kind, texts in entries:
        print(f"\n  entry {a} @+0x{o:X}: {kind}")
        if texts:
            for t in texts:
                print("    TEXT: " + t.replace('\n', ' / '))

print("\n\n=== game-wide sweep: fields with tutorial entries ===")
allr = field_tutorials()
total_tut = sum(1 for es in allr.values() for e in es if e[2] == 'TUT')
print(f"fields with tutorials: {len(allr)}; tutorial entries: {total_tut}")
for fname, entries in sorted(allr.items()):
    kinds = [f"{a}:{k}" for a, _, k, _ in entries]
    print(f"  {fname}: {kinds}")
