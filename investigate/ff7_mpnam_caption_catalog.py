#!/usr/bin/env python3
"""
ff7_mpnam_caption_catalog.py -- game-wide FRIENDLY CAPTION harvest
(v2.30.86 feature, 2026-08-04).

WHY: exits and journey legs speak "To nmkin 2" (maplist internal code)
for any field the player has not personally visited -- the friendly
caption ("Mako Reactor 1") only enters the v2.25 places cache by
STANDING there, because the live MPNAM buffer holds only the CURRENT
field's caption. Testers report the internal-code fallback reads as
deliberately obscured names and is a nuisance, not spoiler protection.
The user's direction (2026-08-04): speak the real place name everywhere
and append "unexplored" for places not yet visited. That needs every
field's caption known OFFLINE -- this harvest. (TODO.txt [JOURNEY]
residuals named "offline MPNAM caption harvest" as exactly this
upgrade path.)

METHOD (all offline, flevel.lgp on disk -- no live game needed):
  1. Parse maplist for field-id -> internal-name (same anchor-checked
     parse as ff7_maplist_catalog.py; id space validated live 2026-07-16
     against field 122 == "nmkin_2").
  2. For every field: decompress (LZS), locate the script section
     (sec_offs[0], +4 skips the section length dword), flow-walk EVERY
     script slot of EVERY entity with the cebix/ff7tools opcode walker
     (verbatim from ff7_line_trigger_catalog.py -- ZERO walk errors over
     all 702 fields when it was built) and collect every reachable
     MPNAM (0x43, one byte arg = index into the field's dialog table).
     A linear byte scan would false-hit 0x43 inside other opcodes'
     operands; the walker only reads real instruction boundaries.
  3. Resolve the MPNAM arg against the field's dialog-string table
     (header u16 at +0x04 = table offset, relative to script section
     start). The table layout is probed per-field with TWO known
     community layouts (count-prefixed vs offset-array-first) and the
     result is anchor-validated below, so a wrong guess cannot ship.
  4. Decode the caption with an EXACT Python mirror of the mod's
     FF7Text::DecodeChar (ff7_text.cpp): bytes 0x00-0x5E -> ascii+0x20,
     0x5F-0xDF -> kExtendedChars table, >= 0xE0 skipped, canonical_ch
     folding (curly quote -> ', dash fold, etc.), trim spaces, then
     TRUNCATE TO 23 CHARS -- the same wchar_t[24] limit PlacesLearn
     stores, so a harvested name and a live-learned name for the same
     field are IDENTICAL STRINGS (dedupe identity and journey-name
     comparisons depend on that).

VALIDATION + MERGE (first run 2026-08-04 taught all three rules):
  ffvii_accessibility_places.txt is captions learned from the LIVE
  MPNAM buffer during real play -- but ONLY the file living in the SAME
  install tree as the flevel.lgp being parsed is comparable ground
  truth: the first run compared the 2013+7H file against the vanilla
  flevel and "found" 4 bogus mismatches that were just Echo-S
  retranslations ("Mako Reactor 1" vs vanilla "No.1 Reactor") -- the
  [[feedback-log-environment-check]] lesson in offline form. Within the
  matching install, THREE legitimate divergence classes exist, so a
  plain equality check cannot be the pass/fail gate:
    (a) conditional MPNAM: reused fields carry two captions (nmkin_* =
        "No.1 Reactor"/"No.5 Reactor") behind a story branch a static
        walk cannot evaluate;
    (b) inheritance: a field whose script sets NO MPNAM shows the
        previous field's caption in the menu, and the live learner
        records that (ids 134/135 "Sector 8");
    (c) never-ran MPNAM: a field CAN own an MPNAM that a given visit
        never executes (id 139 owns "Inside Train", the escape-chapter
        visit displayed the inherited "Last Train from Midgar").
  Resolution = PLAYED EVIDENCE WINS (the project's standing rule): any
  caption the vanilla-runtime places file learned overrides the
  script-derived one in the emitted header. The exact-match rows
  (16/36 on the first run, incl. apostrophe and '7th Heaven' digits)
  are what prove the decoder + table parse; the script HARD-FAILS only
  on structural evidence of a broken parse (walk errors, unparseable
  dialog tables, or zero exact matches when ground truth exists).

OUTPUT: AccessibilityMod/src/ff7_field_captions.h -- kCaptions[788]
  (index = field id, same space as FF7FieldNames), L"" = no caption.
"""
import sys, os, struct, datetime

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"mpnam_caption_catalog_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- opcode table (cebix/ff7tools ff7/field.py, verbatim lengths) ----------------
# Copied from ff7_line_trigger_catalog.py (proven: zero walk errors game-wide).
OPLEN = [
    0, 2, 2, 2, 2, 2, 2, 1,        # 0x00 ret req reqsw reqew preq prqsw prqew retto
    1, 14, 5, 5, -1, -1, 1, 0,     # 0x08 join split sptye gptye - - dskcg spcal
    1, 2, 1, 2, 5, 6, 7, 8,        # 0x10 skip lskip back lback if lif if2 lif2
    7, 8, -1, -1, -1, -1, -1, -1,  # 0x18 if2u lif2u - - - - - -
    10, 1, 4, 2, 2, 8, 1, 1,       # 0x20 mgame tutor btmd2 btrlt wait nfade blink bgmovie
    0, 0, 1, 1, 4, 6, 1, 9,        # 0x28 kawai kawiw pmova slip bgdph bgscr wcls wsizw
    3, 3, 3, 1, 1, 3, 4, 7,        # 0x30 key keyon keyof uc pdira ptura wspcl wnumb
    5, 5, 5, 3, 0, 0, 0, 0,        # 0x38 sttim gold+ gold- chgld hmpmx hmpmx mhmmx hmpmx
    2, 4, 5, 1, -1, 4, -1, 4,      # 0x40 mes mpara mpra2 MPNAM - mp+ - mp-
    6, 3, 1, 1, -1, 4, -1, 4,      # 0x48 ask menu menu btltb - hp+ - hp-
    9, 5, 3, 1, 1, 2, 6, 6,        # 0x50 wsize wmove wmode wrest wclse wrow gwcol swcol
    4, 4, 4, 6, 7, 9, 7, 0,        # 0x58 stitm dlitm ckitm smtra dmtra cmtra shake wait
    9, 1, 4, 5, 5, 0, 8, 0,        # 0x60 mjump scrlo scrlc scrla scr2d scrcc scr2dc scrlw
    8, 1, 6, 8, 0, 3, 2, 5,        # 0x68 scr2dl mpdsp vwoft fade fadew idlck lstmp scrlp
    3, 1, 2, 3, 3, 7, 3, 4,        # 0x70 batle btlon btlmd pgtdr getpc pxyzi plus! pls2!
    3, 4, 2, 2, 2, 2, 1, 2,        # 0x78 mins! mns2! inc! inc2! dec! dec2! tlkon rdmsd
    3, 4, 3, 3, 3, 3, 4, 3,        # 0x80 set set2 biton bitof bitxr plus plus2 minus
    4, 3, 4, 3, 4, 3, 4, 3,        # 0x88 mins2 mul mul2 div div2 remai rema2 and
    4, 3, 4, 3, 4, 2, 2, 2,        # 0x90 and2 or or2 xor xor2 inc inc2 dec
    2, 2, 3, 4, 5, 6, 6, 10,       # 0x98 dec2 randm lbyte hbyte 2byte setx getx srchx
    1, 1, 2, 2, 1, 10, 8, 8,       # 0xa0 pc char dfanm anime visi xyzi xyi xyz
    5, 5, 1, 3, 0, 5, 2, 2,        # 0xa8 move cmove mova tura animw fmove anime anim!
    4, 4, 3, 2, 5, 5, 1, 3,        # 0xb0 canim canm! msped dir turnr turn dira gtdir
    4, 3, 2, 4, 4, 3, -1, 1,       # 0xb8 getaxy getai anim! canim canm! asped - cc
    10, 7, 14, 11, 0, 2, 2, 1,     # 0xc0 jump axyzi lader ofstd ofstw talkR slidR solid
    1, 1, 3, 2, 2, 2, 1, 1,        # 0xc8 prtyp prtym prtye prtyq membq mmb+- mmblk mmbuk
    12, 1, 1, 15, 9, 9, 3, 3,      # 0xd0 line linon mpjpo sline sin cos tlkR2 sldR2
    2, 0, 14, 1, 3, 0, 0, 10,      # 0xd8 pmjmp pmjmp akao2 fcfix ccanm animb turnw mppal
    3, 3, 2, 2, 2, 4, 4, 4,        # 0xe0 bgon bgoff bgrol bgrol bgclr stpal ldpal cppal
    6, 9, 9, 4, 4, 7, 7, 10,       # 0xe8 rtpal adpal mppal stpls ldpls cppal rtpal adpal
    1, 4, 13, 1, 1, 1, 1, 3,       # 0xf0 music se akao musvt musvm mulck bmusc chmph
    1, 0, 2, 1, 1, 5, 2, 0,        # 0xf8 pmvie movie mvief mvcam fmusc cmusc chmst gmovr
]
SPECIAL_LEN = {0xF5: 1, 0xF6: 4, 0xF7: 2, 0xF8: 2, 0xF9: 0, 0xFA: 0,
               0xFB: 1, 0xFC: 1, 0xFD: 2, 0xFE: 0, 0xFF: 0}
OP_RET, OP_RETTO, OP_SPCAL, OP_KAWAI = 0x00, 0x07, 0x0F, 0x28
OP_GMOVR = 0xFF
OP_MPNAM = 0x43

def instr_size(code, off):
    op = code[off]
    ln = OPLEN[op]
    if ln < 0:
        return None
    if op == OP_SPCAL:
        sub = code[off + 1] if off + 1 < len(code) else None
        if sub not in SPECIAL_LEN:
            return None
        return SPECIAL_LEN[sub] + 2
    if op == OP_KAWAI:
        sz = code[off + 1] if off + 1 < len(code) else 0
        return sz if sz >= 3 else None
    return ln + 1

def branch_target(code, off):
    op = code[off]
    if op == 0x10:                                   # skip
        return off + code[off + 1] + 1
    if op == 0x11:                                   # lskip
        return off + (code[off + 1] | (code[off + 2] << 8)) + 1
    if op == 0x12:                                   # back
        return off - code[off + 1]
    if op == 0x13:                                   # lback
        return off - (code[off + 1] | (code[off + 2] << 8))
    if op == 0x14:                                   # if
        return off + code[off + 5] + 5
    if op == 0x15:                                   # lif
        return off + (code[off + 5] | (code[off + 6] << 8)) + 5
    if op in (0x16, 0x18):                           # if2/if2u
        return off + code[off + 7] + 7
    if op in (0x17, 0x19):                           # lif2/lif2u
        return off + (code[off + 7] | (code[off + 8] << 8)) + 7
    if op in (0x30, 0x31, 0x32):                     # key/keyon/keyof
        return off + code[off + 3] + 3
    if op in (0xCB, 0xCC):                           # prtyq membq
        return off + code[off + 2] + 2
    return None

def walk(code, entry, errors):
    """Flow-reachable {offset: opcode} from entry (bounded, tolerant)."""
    seen = {}
    stack = [entry]
    guard = 8192
    while stack and guard > 0:
        off = stack.pop()
        while 0 <= off < len(code) and off not in seen and guard > 0:
            guard -= 1
            op = code[off]
            sz = instr_size(code, off)
            if sz is None:
                errors.append((off, op))
                break
            seen[off] = op
            if op in (OP_RET, OP_RETTO, OP_GMOVR):
                break
            t = branch_target(code, off)
            if t is not None:
                if op in (0x10, 0x11, 0x12, 0x13):   # unconditional
                    off = t
                    continue
                stack.append(t)                      # conditional: both paths
            off += sz
    return seen

# -- FF7 text decode: EXACT mirror of FF7Text::DecodeChar (ff7_text.cpp) ---------
# kExtendedChars (ff7tk eng[] table), index = byte - 0x5F. Any drift between
# this dict and the C++ table would break the learned-vs-harvested string
# identity, so the layout below matches the C++ initializer row-for-row.
_EXT = {}
def _ext(row_base, chars):
    for i, ch in enumerate(chars):
        if ch:
            _EXT[row_base + i] = ch
_ext(0x60, ['\xC4', '\xC5', '\xC7', '\xC9', '\xD1', '\xD6', '\xDC'])
_ext(0x67, ['\xE1', '\xE0', '\xE2', '\xE4', '\xE3', '\xE5', '\xE7', '\xE9', '\xE8'])
_ext(0x70, ['\xEA', '\xEB', '\xED', '\xEC', '\xEE', '\xEF'])
_ext(0x76, ['\xF1', '\xF3', '\xF2', '\xF4', '\xF6', '\xF5'])
_ext(0x7C, ['\xFA', '\xF9', '\xFB', '\xFC'])
_ext(0x80, ['\u2318', '\xB0', '\xA2', '\xA3', '\xD9', '\xDB', '\xB6', '\xDF'])
_ext(0x88, ['\xAE', '\xA9', '\u2122', '\xB4', '\xA8', '\u2260', '\xC6', '\xD8'])
_ext(0x90, ['\u221E', '\xB1', '\u2264', '\u2265', '\xA5', '\xB5', '\u2202', '\u03A3'])
_ext(0x98, ['\u03A0', '\u03C0', '\u2321', '\xAA', '\xBA', '\u03A9', '\xE6', '\xF8'])
_ext(0xA0, ['\xBF', '\xA1', '\xAC', '\u221A', '\u0192', '\u2248', '\u2206', '\xAB'])
_ext(0xA8, ['\xBB', '\u2026', None, '\xC0', '\xC3', '\xD5', '\u0152', '\u0153'])
_ext(0xB0, ['\u2013', '\u2014', '\u201C', '\u201D', '\u2018', '\u2019', '\xF7', '\u25CA'])
_ext(0xB8, ['\xFF', '\u0178', '\u2044', '\xA4', '\u2039', '\u203A', '\uFB01', '\uFB02'])
_ext(0xC0, ['\u25A0', '\u25AA', '\u201A', '\u201E', '\u2030', '\xC2', '\xCA', '\xC1'])
_ext(0xC8, ['\xCB', '\xC8', '\xCD', '\xCE', '\xCF', '\xCC', '\xD3', '\xD4'])
_ext(0xD0, [None, '\xD2', '\xD9', '\xDB'])

def _canonical(ch):
    o = ord(ch)
    if 0x20 <= o <= 0x7E:
        return ch
    if o in (0x2018, 0x2019, 0x201A, 0x201B):
        return "'"
    if o in (0x201C, 0x201D, 0x201E):
        return '"'
    if o in (0x2013, 0x2014):
        return '-'
    if o == 0x2026:
        return '.'
    if o == 0xBF:
        return '?'
    if o == 0xA1:
        return '!'
    if o in (0xAB, 0xBB):
        return '"'
    if o in (0x2039, 0x203A):
        return "'"
    if 0xC0 <= o <= 0xFF:
        return ch
    return None

def decode_char(b):
    """FF7Text::DecodeChar mirror: speakable char or None."""
    if b <= 0x5E:
        return _canonical(chr(b + 0x20))
    if b <= 0xDF:
        ch = _EXT.get(b)
        return _canonical(ch) if ch else None
    return None                      # 0xE0+: newline/token/terminator bytes

def decode_caption(buf, off):
    """FriendlyLocationName + PlacesLearn mirror: per-byte decode to the
    0xFF terminator, trim spaces, truncate to 23 chars (wchar_t[24])."""
    out = []
    while off < len(buf):
        b = buf[off]
        if b == 0xFF:
            break
        ch = decode_char(b)
        if ch:
            out.append(ch)
        off += 1
    s = ''.join(out).strip(' ')
    return s[:23]

# -- flevel loading (same helpers as the other catalogs) --------------------------
CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found")
    sys.exit(1)
print(f"Reading: {lgp_path}")
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

# maplist: name -> [field ids]  (32-byte entries; anchor-checked start)
mo = next((o for nm, o in toc if nm == 'maplist'), None)
mlen = struct.unpack_from('<I', data, mo + 20)[0]
mraw = data[mo + 24:mo + 24 + mlen]
start = next((s for s in (0, 2)
              if mraw[s + 122 * 32:s + 123 * 32].split(b'\0')[0] == b'nmkin_2'),
             None)
if start is None:
    print("ERROR: maplist anchor failed")
    sys.exit(1)
name_to_ids = {}
n_ids = 0
for off in range(start, len(mraw) - 31, 32):
    nm = mraw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace').lower()
    if nm:
        name_to_ids.setdefault(nm, []).append(n_ids)
    n_ids += 1
print(f"maplist: {n_ids} ids, {len(name_to_ids)} named\n")
KCOUNT = 788   # must equal FF7FieldNames::kCount (asserted below)
if n_ids != KCOUNT:
    print(f"ERROR: maplist id count {n_ids} != FF7FieldNames::kCount {KCOUNT}")
    sys.exit(1)

# -- dialog-string table reader ---------------------------------------------------
# The script section header's u16 at +0x04 is the dialog table offset
# (relative to the section start). Two documented layouts exist in the
# community tooling; probe both and demand internal consistency, then the
# anchor validation at the end confirms the winner on real play data.
def dialog_table(dec, sc, sec_end):
    base = sc + struct.unpack_from('<H', dec, sc + 4)[0]
    if base + 2 > sec_end:
        return None
    span = sec_end - base

    def offsets_ok(offs, hdr_len):
        return offs and all(hdr_len <= o < span for o in offs)

    # Layout A: u16 count, then count u16 offsets (relative to base).
    cnt = struct.unpack_from('<H', dec, base)[0]
    if 0 < cnt <= 1024 and base + 2 + cnt * 2 <= sec_end:
        offs = list(struct.unpack_from(f'<{cnt}H', dec, base + 2))
        if offsets_ok(offs, 2 + cnt * 2):
            return ('A', base, offs)

    # Layout B: offset array first; count = first_offset / 2.
    first = struct.unpack_from('<H', dec, base)[0]
    if first >= 2 and first % 2 == 0:
        cnt = first // 2
        if 0 < cnt <= 1024 and base + cnt * 2 <= sec_end:
            offs = list(struct.unpack_from(f'<{cnt}H', dec, base))
            if offsets_ok(offs, cnt * 2):
                return ('B', base, offs)
    return None

# -- per-field harvest ------------------------------------------------------------
captions = [''] * KCOUNT             # index = field id
stats = dict(fields=0, with_mpnam=0, decoded=0, walk_errors=0,
             multi_id=0, table_fail=0, layouts={'A': 0, 'B': 0})
multi_detail = []

for fname, entry_off in toc:
    if fname not in name_to_ids:
        continue
    flen = struct.unpack_from('<I', data, entry_off + 20)[0]
    raw = data[entry_off + 24:entry_off + 24 + flen]
    if len(raw) < 8:
        continue
    dec = lzs_decompress(raw[4:], 4 * 1024 * 1024)
    if len(dec) < 6 + 36:
        continue
    sec_offs = struct.unpack_from('<9I', dec, 6)
    if sec_offs[0] != 0x2A or any(sec_offs[i] >= sec_offs[i + 1]
                                  for i in range(8)):
        continue
    sc = sec_offs[0] + 4
    if sc + 0x20 > len(dec):
        continue
    n_ent = dec[sc + 2]
    wstr = struct.unpack_from('<H', dec, sc + 4)[0]
    n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
    tab = 0x20 + n_ent * 8 + n_akao * 4
    if sc + tab + n_ent * 64 > len(dec) or wstr <= tab:
        continue
    code = dec[sc:sc + wstr]
    stats['fields'] += 1

    def slot_offs(e):
        return [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
                for s in range(32)]

    # Collect every reachable MPNAM's text id. Ordered slot-major (slot 0 =
    # init scripts first) so a field with several MPNAM sites prefers the
    # one the engine runs at field entry.
    errors = []
    found = []                       # (slot, entity, offset, text_id)
    for s in range(32):
        for e in range(n_ent):
            offs = slot_offs(e)
            if offs[s] >= len(code):
                continue
            reach = walk(code, offs[s], errors)
            for off, op in reach.items():
                if op == OP_MPNAM and off + 1 < len(code):
                    found.append((s, e, off, code[off + 1]))
    stats['walk_errors'] += len(errors)
    if not found:
        continue
    stats['with_mpnam'] += 1
    found.sort()
    ids = {f[3] for f in found}
    if len(ids) > 1:
        stats['multi_id'] += 1
        multi_detail.append((fname, sorted(ids)))
    text_id = found[0][3]

    # The next section boundary caps the dialog table span. sec_offs are
    # absolute-ish (each points at a section length dword) -- section 1
    # starts at sec_offs[1]; dialogs live inside section 0's span.
    sec_end = min(len(dec), sec_offs[1] + 4)
    dt = dialog_table(dec, sc, sec_end)
    if dt is None:
        stats['table_fail'] += 1
        print(f"  WARN {fname}: dialog table unparseable (MPNAM id {text_id})")
        continue
    layout, base, offs = dt
    stats['layouts'][layout] += 1
    if text_id >= len(offs):
        stats['table_fail'] += 1
        print(f"  WARN {fname}: MPNAM id {text_id} >= table count {len(offs)}")
        continue
    cap = decode_caption(dec, base + offs[text_id])
    if not cap:
        continue
    stats['decoded'] += 1
    for fid in name_to_ids[fname]:
        captions[fid] = cap

print(f"\nfields walked: {stats['fields']}, with MPNAM: {stats['with_mpnam']}, "
      f"captions decoded: {stats['decoded']}")
print(f"walk errors: {stats['walk_errors']}, table layout uses: {stats['layouts']}, "
      f"table failures: {stats['table_fail']}, multi-id fields: {stats['multi_id']}")
for fname, ids in multi_detail[:20]:
    print(f"  multi-MPNAM {fname}: text ids {ids} (took first in slot order)")

# -- VALIDATION + MERGE vs the live-learned places file ---------------------------
# Only the places file in the SAME install tree as the parsed flevel.lgp is
# comparable (see header: the 2013+7H file learned Echo-S retranslations).
# Exact matches prove the decoder; learned values override the header
# (played evidence wins); divergences are reported, never fatal by
# themselves -- see the three divergence classes in the header comment.
# flevel.lgp sits at <mod dir>\data\field\flevel.lgp for both installs
# (mod dir = workingdir for 2026, game root for 2013), so the places file
# is exactly three levels up.
places_file = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(lgp_path))),
    'ffvii_accessibility_places.txt')
exact = 0
diverged = 0
overrides = 0
if not os.path.isfile(places_file):
    print(f"\nvalidation: {places_file} not present -- no ground truth, "
          f"header ships script-derived captions only")
else:
    print(f"\nvalidating/merging against {places_file}")
    for line in open(places_file, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        fid_s, learned = line.split('=', 1)
        fid = int(fid_s)
        if fid <= 0 or fid >= KCOUNT or not learned:
            continue
        harvested = captions[fid]
        if harvested == learned:
            exact += 1
            print(f"  id {fid}: '{learned}' exact match")
        else:
            diverged += 1
            why = ("inheritance (no MPNAM in field)" if not harvested
                   else "conditional/never-ran MPNAM")
            print(f"  id {fid}: learned '{learned}' overrides harvested "
                  f"'{harvested or '(empty)'}' -- {why}")
            captions[fid] = learned
            overrides += 1
    print(f"\nvalidation: {exact} exact matches, {diverged} divergences "
          f"(all overridden with played evidence)")
    if exact == 0:
        print("VALIDATION FAILED: ground truth exists but NOTHING matched "
              "exactly -- decoder or table parse is broken; header NOT written")
        sys.exit(1)
if stats['walk_errors'] or stats['table_fail']:
    print(f"VALIDATION FAILED: structural errors (walk={stats['walk_errors']}, "
          f"table={stats['table_fail']}) -- header NOT written")
    sys.exit(1)

# -- emit header ------------------------------------------------------------------
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        '..', 'AccessibilityMod', 'src', 'ff7_field_captions.h')
out_path = os.path.normpath(out_path)

def wide_literal(s):
    """Emit a C wide-string literal. Non-ASCII chars use \\xNN escapes; the
    literal is split after every escape (L"Caf\\xE9" L"s") so a following
    hex-like character can never be absorbed into the escape."""
    if not s:
        return 'L""'
    parts = ['L"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            parts.append('\\"')
        elif ch == '\\':
            parts.append('\\\\')
        elif 0x20 <= o <= 0x7E:
            parts.append(ch)
        else:
            parts.append(f'\\x{o:X}" L"')
    parts.append('"')
    lit = ''.join(parts)
    return lit.replace(' L""', '') if lit.endswith(' L""') else lit

with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(f"""/*
 * ff7_field_captions.h -- GENERATED FILE, do not edit by hand.
 *
 * Every field's FRIENDLY caption ("Mako Reactor 1"), harvested offline
 * from each field's own MPNAM opcode (0x43) in flevel.lgp by
 * investigate/ff7_mpnam_caption_catalog.py ({datetime.date.today()}).
 * Index = field id (the FF7FieldNames::kNames id space). L"" = the
 * field's scripts set no MPNAM (at runtime it inherits the previous
 * field's caption -- callers fall through to the visited-places cache
 * and then the internal maplist name).
 *
 * Decoded with an exact mirror of FF7Text::DecodeChar and truncated to
 * 23 chars, so an entry here is byte-identical to what PlacesLearn
 * stores when the player actually visits the field -- name identity
 * (dedupe, journey comparisons) is preserved across the two sources.
 * Validated against the live-learned ffvii_accessibility_places.txt
 * captions from real play (ids 116-124) at generation time.
 *
 * WHY THIS EXISTS (v2.30.86): exits/journeys used to speak internal map
 * codes ("To nmkin 2") for unvisited destinations; testers read that as
 * name-obscuring. Real names now speak everywhere, with ", unexplored"
 * appended by the callers when the visited cache has no entry.
 */

#pragma once

namespace FF7FieldCaptions {{

constexpr int kCount = {KCOUNT};

inline const wchar_t* const kCaptions[kCount] = {{
""")
    for fid in range(KCOUNT):
        f.write(f"    {wide_literal(captions[fid])},   // {fid}\n")
    f.write("""};

// The harvested caption for a field id, or nullptr when none exists.
inline const wchar_t* Get(int field_id)
{
    if (field_id < 0 || field_id >= kCount || !kCaptions[field_id][0])
        return nullptr;
    return kCaptions[field_id];
}

} // namespace FF7FieldCaptions
""")
named = sum(1 for c in captions if c)
print(f"\nwrote {out_path}: {named}/{KCOUNT} ids with captions")
print("sample:", [(fid, captions[fid]) for fid in (116, 119, 124)])
