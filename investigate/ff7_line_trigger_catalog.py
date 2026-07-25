#!/usr/bin/env python3
"""
ff7_line_trigger_catalog.py -- game-wide LINE-trigger BEHAVIOR catalog
(v2.30.23 feature, 2026-07-25).

WHY: the Triggers category speaks raw dev names ("border", "pinball",
"kaisou") with no hint of what each line DOES. The 2026-07-25 play session
showed the cost: the player stood on the hideout's 'border' line (a
cutscene trigger) trying to leave, while the actual exit was the
'pinball' line (cross it -> REQ cloud.s5 -> MAPJUMP 154). A sighted
player sees a lift platform vs a patch of floor; the mod should speak
that difference: "pinball, exit to Seventh Heaven" vs "border, scene".

METHOD: walk every field's script section (index 0) with a real opcode
walker -- opcode lengths, jump-target math, and exit opcodes taken
VERBATIM from cebix/ff7tools ff7/field.py (production decompiler, the
same table Makou Reactor uses). For each entity whose init script
declares a LINE (0xD0) or SLINE (0xD3):

  - flow-walk each script slot (sequential flow + branch targets, stop
    at ret/retto/gmovr) to get the REACHABLE instruction set;
  - expand ONE hop through req/reqsw/reqew (entity, pri<<5|script) --
    the hideout pinball line reaches its MAPJUMP through exactly such a
    hop (reqsw cloud.s5, verified against the 2026-07-25 script dump);
  - classify: MJUMP (0x60) reachable -> EXIT (+ dest field id, + whether
    only the [OK] slot reaches it); else LADER (0xC2) -> CLIMB; else
    non-empty [OK] slot (script index 1) -> OK; else any non-empty
    cross slot (indices 2..6) -> SCENE; else INERT.

LINE-entity script slot semantics (community-documented): for a line
entity, script index 1 = [OK] pressed on the line, 2/3 = move on it,
4 = Go (cross), 5 = Go1x, 6 = GoAway.

OUTPUT: AccessibilityMod/src/ff7_line_trigger_catalog.h -- sorted
{field_id, entity_id, kind, dest_field} entries + lookup helper. Field
ids from the maplist (same parse as ff7_maplist_catalog.py); fields not
in the maplist (dev leftovers) are skipped -- they are unreachable at
runtime.

VALIDATION (printed at the end):
  - mds7pb_2 (155): pinball -> EXIT dest=154 cross-activated;
    border2 -> SCENE; TV -> SCENE.   (2026-07-25 hand-decoded dump)
  - nmkin_2 (122): ladder lines -> CLIMB.
  - walk error counts (unknown opcodes, runaway KAWAI) -- must be ~0
    for the table to be trusted.
"""
import sys, os, struct, datetime

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"line_trigger_catalog_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
# value = OPERAND length; instruction size = value + 1. -1 = undefined opcode.
OPLEN = [
    0, 2, 2, 2, 2, 2, 2, 1,        # 0x00 ret req reqsw reqew preq prqsw prqew retto
    1, 14, 5, 5, -1, -1, 1, 0,     # 0x08 join split sptye gptye - - dskcg spcal
    1, 2, 1, 2, 5, 6, 7, 8,        # 0x10 skip lskip back lback if lif if2 lif2
    7, 8, -1, -1, -1, -1, -1, -1,  # 0x18 if2u lif2u - - - - - -
    10, 1, 4, 2, 2, 8, 1, 1,       # 0x20 mgame tutor btmd2 btrlt wait nfade blink bgmovie
    0, 0, 1, 1, 4, 6, 1, 9,        # 0x28 kawai kawiw pmova slip bgdph bgscr wcls wsizw
    3, 3, 3, 1, 1, 3, 4, 7,        # 0x30 key keyon keyof uc pdira ptura wspcl wnumb
    5, 5, 5, 3, 0, 0, 0, 0,        # 0x38 sttim gold+ gold- chgld hmpmx hmpmx mhmmx hmpmx
    2, 4, 5, 1, -1, 4, -1, 4,      # 0x40 mes mpara mpra2 mpnam - mp+ - mp-
    6, 3, 1, 1, -1, 4, -1, 4,      # 0x48 ask menu menu btltb - hp+ - hp-
    9, 5, 3, 1, 1, 2, 6, 6,        # 0x50 wsize wmove wmode wrest wclse wrow gwcol swcol
    4, 4, 4, 6, 7, 9, 7, 0,        # 0x58 stitm dlitm ckitm smtra dmtra cmtra shake wait
    9, 1, 4, 5, 5, 0, 8, 0,        # 0x60 MJUMP scrlo scrlc scrla scr2d scrcc scr2dc scrlw
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
    10, 7, 14, 11, 0, 2, 2, 1,     # 0xc0 jump axyzi LADER ofstd ofstw talkR slidR solid
    1, 1, 3, 2, 2, 2, 1, 1,        # 0xc8 prtyp prtym prtye prtyq membq mmb+- mmblk mmbuk
    12, 1, 1, 15, 9, 9, 3, 3,      # 0xd0 LINE linon mpjpo SLINE sin cos tlkR2 sldR2
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
OP_MJUMP, OP_LADER, OP_LINE, OP_SLINE = 0x60, 0xC2, 0xD0, 0xD3
OP_REQ, OP_REQSW, OP_REQEW = 0x01, 0x02, 0x03

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
    """Jump/branch target offset, or None (cebix targetOffset verbatim)."""
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
    """Flow-reachable {offset: opcode} from entry. Bounded, tolerant:
    an undecodable instruction abandons that path (counted), not the
    whole walk."""
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
fid = 0
for off in range(start, len(mraw) - 31, 32):
    nm = mraw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace').lower()
    if nm:
        name_to_ids.setdefault(nm, []).append(fid)
    fid += 1
print(f"maplist: {fid} ids, {len(name_to_ids)} named\n")

# -- per-field classification -----------------------------------------------------
KINDS = ["EXIT", "EXIT_OK", "CLIMB", "OK", "SCENE", "INERT"]
K_EXIT, K_EXIT_OK, K_CLIMB, K_OK, K_SCENE, K_INERT = range(6)

entries = []          # (field_id, ent, kind, dest)
stats = dict(fields=0, lines=0, walk_errors=0, preq_skipped=0,
             multi_dest=0, kinds=[0] * 6)
detail = {}           # field_name -> [(ent, ename, kind, dest, coords)]

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
    code = dec[sc:sc + wstr]           # script code block (offsets relative)
    stats['fields'] += 1

    def slot_offs(e):
        return [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
                for s in range(32)]

    ename = lambda e: dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8] \
        .split(b'\0')[0].decode('ascii', 'replace')

    # cache walks: (entity, slot) -> reachable dict
    walk_cache = {}
    def slot_walk(e, s, errors):
        key = (e, s)
        if key not in walk_cache:
            offs = slot_offs(e)
            if s >= 32 or offs[s] >= len(code):
                walk_cache[key] = {}
            else:
                walk_cache[key] = walk(code, offs[s], errors)
        return walk_cache[key]

    for e in range(n_ent):
        errors = []
        init = slot_walk(e, 0, errors)
        line_op = next((o for o, op in init.items()
                        if op in (OP_LINE, OP_SLINE)), None)
        if line_op is None:
            continue
        stats['lines'] += 1
        coords = struct.unpack_from('<6h', code, line_op + 1) \
            if code[line_op] == OP_LINE else None

        # classify slots 1..6
        dests = []
        exit_from_cross = False
        exit_from_ok = False
        lader = False
        ok_nonempty = False
        cross_nonempty = False
        for s in range(1, 7):
            reach = dict(slot_walk(e, s, errors))
            # one-hop REQ expansion
            for off, op in list(reach.items()):
                if op in (OP_REQ, OP_REQSW, OP_REQEW):
                    te = code[off + 1]
                    ts = code[off + 2] & 0x1F
                    if te < n_ent:
                        reach.update(slot_walk(te, ts, errors))
                elif op in (0x04, 0x05, 0x06):
                    stats['preq_skipped'] += 1
            ops = set(reach.values())
            nonempty = bool(ops - {OP_RET})
            if s == 1:
                ok_nonempty = nonempty
            else:
                cross_nonempty = cross_nonempty or nonempty
            if OP_MJUMP in ops:
                for off, op in reach.items():
                    if op == OP_MJUMP:
                        dests.append(struct.unpack_from('<H', code, off + 1)[0])
                if s == 1:
                    exit_from_ok = True
                else:
                    exit_from_cross = True
            if OP_LADER in ops:
                lader = True
        stats['walk_errors'] += len(errors)

        if exit_from_cross or exit_from_ok:
            kind = K_EXIT if exit_from_cross else K_EXIT_OK
            # A single unambiguous MAPJUMP destination is speakable
            # ("exit to Seventh Heaven"); conditional multi-destination
            # exits (story-dependent MAPJUMPs — the lift goes up OR down)
            # record -1 so the mod says just "exit" instead of guessing
            # wrong half the time.
            uniq = set(dests)
            dest = dests[0] if len(uniq) == 1 else -1
            if len(uniq) > 1:
                stats['multi_dest'] += 1
        elif lader:
            kind, dest = K_CLIMB, -1
        elif ok_nonempty:
            kind, dest = K_OK, -1
        elif cross_nonempty:
            kind, dest = K_SCENE, -1
        else:
            kind, dest = K_INERT, -1
        stats['kinds'][kind] += 1

        for fid2 in name_to_ids[fname]:
            entries.append((fid2, e, kind, dest))
        detail.setdefault(fname, []).append(
            (e, ename(e), KINDS[kind], dest, coords))

entries.sort()
print(f"fields walked        : {stats['fields']}")
print(f"line entities        : {stats['lines']}")
print(f"walk errors          : {stats['walk_errors']}")
print(f"preq hops skipped    : {stats['preq_skipped']}")
print(f"multi-dest exits     : {stats['multi_dest']}")
for k, n in zip(KINDS, stats['kinds']):
    print(f"  {k:8s}: {n}")

# -- validation ------------------------------------------------------------------
print("\n=== VALIDATION ===")
ok = True
v = {ent_name: kind for _, ent_name, kind, _, _ in detail.get('mds7pb_2', [])}
checks = [('mds7pb_2', 'pinball', 'EXIT'), ('mds7pb_2', 'border2', 'SCENE'),
          ('mds7pb_2', 'TV', 'SCENE')]
for fld, en, want in checks:
    got = {n: k for _, n, k, _, _ in detail.get(fld, [])}.get(en, 'MISSING')
    tag = "OK " if got == want else "FAIL"
    if got != want:
        ok = False
    print(f"  [{tag}] {fld}/{en}: want {want}, got {got}")
pin = [d for _, n, k, d, _ in detail.get('mds7pb_2', []) if n == 'pinball']
if pin and pin[0] == 154:
    print("  [OK ] mds7pb_2/pinball dest=154 (mds7pb_1)")
else:
    ok = False
    print(f"  [FAIL] mds7pb_2/pinball dest={pin} (want 154)")
lads = [k for _, n, k, _, _ in detail.get('nmkin_2', []) if 'lad' in n.lower()]
print(f"  nmkin_2 ladder-named line kinds: {lads} "
      f"({'OK' if lads and all(k == 'CLIMB' for k in lads) else 'CHECK'})")
print("\nSample fields:")
for fld in ('mds7pb_2', 'mds7pb_1', 'mds7', 'nmkin_2', 'md1stin', 'mds7st3'):
    for row in detail.get(fld, []):
        print(f"  {fld}: ent={row[0]} '{row[1]}' {row[2]} dest={row[3]} "
              f"line={row[4]}")

# -- header generation -----------------------------------------------------------
hdr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        '..', 'AccessibilityMod', 'src',
                        'ff7_line_trigger_catalog.h')
hdr_path = os.path.normpath(hdr_path)
with open(hdr_path, 'w', encoding='utf-8', newline='\n') as h:
    h.write(f"""// ff7_line_trigger_catalog.h -- GENERATED by
// investigate/ff7_line_trigger_catalog.py ({datetime.date.today()}); do not
// hand-edit. Re-run the script after any game-data change.
//
// What each field's LINE triggers DO, classified offline by walking the
// field scripts (opcode table from cebix/ff7tools -- see the generator's
// doc comment for the method and validation). Consumed by the Triggers
// category so a line can speak as "pinball, exit to Seventh Heaven"
// instead of a bare dev name (the 2026-07-25 hideout lesson: the player
// stood on a cutscene 'border' line hunting for the way upstairs while
// the real exit was the 'pinball' lift line).
//
// Keyed by (maplist field id, owning entity id) -- both available at
// runtime from the engine's line array (+0x0D entity id, v2.17).
// Fields absent from the maplist are omitted (unreachable at runtime).
//
// stats: {stats['fields']} fields, {stats['lines']} line entities,
// {stats['walk_errors']} walk errors, kinds: """
            + ", ".join(f"{k}={n}" for k, n in zip(KINDS, stats['kinds']))
            + """
#pragma once
#include <cstdint>

namespace FF7LineCatalog {

enum LineKind : uint8_t {
    LK_EXIT    = 0,  // crossing it leads to a MAPJUMP (dest below)
    LK_EXIT_OK = 1,  // MAPJUMP only via its [OK] script -- press OK on it
    LK_CLIMB   = 2,  // LADER reachable -- a climbable (ladder/pipe)
    LK_OK      = 3,  // [OK] script does something; no field exit
    LK_SCENE   = 4,  // only walk-on/cross scripts; scene/cutscene trigger
    LK_INERT   = 5,  // no non-empty scripts (rare)
};

struct LineInfo {
    uint16_t field_id;
    uint8_t  entity_id;
    uint8_t  kind;
    int16_t  dest_field;   // LK_EXIT/LK_EXIT_OK: MAPJUMP target; else -1
};

// Sorted by (field_id, entity_id) for binary search.
inline constexpr LineInfo kLines[] = {
""")
    for fid2, e, kind, dest in entries:
        h.write(f"    {{{fid2}, {e}, {kind}, {dest}}},\n")
    h.write("""};

inline const LineInfo* Find(uint16_t field_id, uint8_t entity_id)
{
    size_t lo = 0, hi = sizeof(kLines) / sizeof(kLines[0]);
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        const LineInfo& e = kLines[mid];
        if (e.field_id < field_id ||
            (e.field_id == field_id && e.entity_id < entity_id))
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < sizeof(kLines) / sizeof(kLines[0]) &&
        kLines[lo].field_id == field_id && kLines[lo].entity_id == entity_id)
        return &kLines[lo];
    return nullptr;
}

} // namespace FF7LineCatalog
""")
print(f"\nHeader written: {hdr_path} ({len(entries)} entries)")
print("VALIDATION VERDICT:", "PASS" if ok else "FAIL -- do not ship")
