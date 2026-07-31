#!/usr/bin/env python3
"""
ff7_prop_interact_catalog.py -- game-wide catalog of TALK-SCRIPTED MODEL
entities (v2.30.45 feature work, 2026-07-31).

WHY (two tester reports, 2026-07-31):
  1. "Wall switches such as the elevator button in the reactor need to be
     listed in the pathfinder." Interactive props (buttons, levers,
     valves) are MODELS whose labels classify as scenery, so the
     v2.30.18 MC_SCENERY filter hides them from every category -- the
     exact tradeoff deliberately deferred in the v2.30.36 review sweep
     ("future offline-catalog whitelist of talk-scripted fieldbg
     props"). This script builds that whitelist.
  2. "Items don't disappear from the field after they are picked up."
     Before hunting the engine's visibility byte, PROVE the hide
     mechanism: if pickup talk scripts consistently reach VISI (0xA4),
     then the byte written by the VISI opcode handler is the runtime
     signal to filter on (handler disasm = ff7_visi_handler_disasm.py,
     the companion script).

METHOD: same parsing as ff7_line_trigger_catalog.py (LGP TOC -> LZS ->
section table; opcode lengths/branch math verbatim from cebix/ff7tools).
For every SCRIPT entity in every maplist field:
  - walk the init slot (0); entities declaring LINE/SLINE are line
    entities (already cataloged) -> skipped here;
  - find CHAR (0xA1) in init: its operand binds the entity to a MODEL
    LOADER index -> this is a model entity; no CHAR -> logic entity,
    skipped;
  - walk the TALK slot (script index 1 -- the same slot the line
    catalog validated as [OK] for lines; for models the engine runs it
    on an in-range OK press) with the line catalog's one-hop REQ
    expansion;
  - record: talk-script non-emptiness + which EVIDENCE ops it reaches:
    STITM 0x58 (grants an item -- pickup), SMTRA 0x5B (grants materia),
    VISI 0xA4 (model visibility -- the suspected hide mechanism),
    MES 0x40 / ASK 0x48, MJUMP 0x60, GOLD+ 0x39.

OUTPUT:
  - AccessibilityMod/src/ff7_prop_catalog.h: {field_id, entity_id,
    model_idx, flags} for every model entity with a non-empty talk
    script. The MOD intersects this with its own runtime label
    classification: models it would have shown anyway (people, chests,
    items, saves) ignore the entry; models it FILTERED as scenery get
    resurrected as interactive props ("switch"). Python deliberately
    does NOT replicate the C++ label classifier -- one classifier, one
    place (the v2.18.2 rule).
  - Pickup-mechanism stats: of all entities whose talk grants loot
    (STITM/SMTRA), how many reach VISI in the same walk. A high ratio
    = VISI is THE hide mechanism and the handler hunt is justified.
  - Full dumps for the reactor route fields (md1_1..nmkin_5) and the
    known-ground-truth fields for eyeball validation.

VALIDATION:
  - nmkin_* / md1_* must show elevator/button-ish entities with talk
    scripts (the tester pressed one -- it exists);
  - mds7st3 potion pickups (if modeled) must show STITM evidence;
  - md1stin's known 10 models must all resolve loader labels;
  - walk errors ~0.
"""
import sys, os, struct, datetime
from collections import defaultdict

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"prop_interact_catalog_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- opcode table (cebix/ff7tools, identical to ff7_line_trigger_catalog.py) -----
OPLEN = [
    0, 2, 2, 2, 2, 2, 2, 1,
    1, 14, 5, 5, -1, -1, 1, 0,
    1, 2, 1, 2, 5, 6, 7, 8,
    7, 8, -1, -1, -1, -1, -1, -1,
    10, 1, 4, 2, 2, 8, 1, 1,
    0, 0, 1, 1, 4, 6, 1, 9,
    3, 3, 3, 1, 1, 3, 4, 7,
    5, 5, 5, 3, 0, 0, 0, 0,
    2, 4, 5, 1, -1, 4, -1, 4,
    6, 3, 1, 1, -1, 4, -1, 4,
    9, 5, 3, 1, 1, 2, 6, 6,
    4, 4, 4, 6, 7, 9, 7, 0,
    9, 1, 4, 5, 5, 0, 8, 0,
    8, 1, 6, 8, 0, 3, 2, 5,
    3, 1, 2, 3, 3, 7, 3, 4,
    3, 4, 2, 2, 2, 2, 1, 2,
    3, 4, 3, 3, 3, 3, 4, 3,
    4, 3, 4, 3, 4, 3, 4, 3,
    4, 3, 4, 3, 4, 2, 2, 2,
    2, 2, 3, 4, 5, 6, 6, 10,
    1, 1, 2, 2, 1, 10, 8, 8,
    5, 5, 1, 3, 0, 5, 2, 2,
    4, 4, 3, 2, 5, 5, 1, 3,
    4, 3, 2, 4, 4, 3, -1, 1,
    10, 7, 14, 11, 0, 2, 2, 1,
    1, 1, 3, 2, 2, 2, 1, 1,
    12, 1, 1, 15, 9, 9, 3, 3,
    2, 0, 14, 1, 3, 0, 0, 10,
    3, 3, 2, 2, 2, 4, 4, 4,
    6, 9, 9, 4, 4, 7, 7, 10,
    1, 4, 13, 1, 1, 1, 1, 3,
    1, 0, 2, 1, 1, 5, 2, 0,
]
SPECIAL_LEN = {0xF5: 1, 0xF6: 4, 0xF7: 2, 0xF8: 2, 0xF9: 0, 0xFA: 0,
               0xFB: 1, 0xFC: 1, 0xFD: 2, 0xFE: 0, 0xFF: 0}
OP_RET, OP_RETTO, OP_SPCAL, OP_KAWAI = 0x00, 0x07, 0x0F, 0x28
OP_GMOVR = 0xFF
OP_LINE, OP_SLINE = 0xD0, 0xD3
OP_REQ, OP_REQSW, OP_REQEW = 0x01, 0x02, 0x03
OP_CHAR = 0xA1
# evidence ops
OP_STITM, OP_SMTRA, OP_VISI = 0x58, 0x5B, 0xA4
OP_MES, OP_ASK, OP_MJUMP, OP_GOLDP = 0x40, 0x48, 0x60, 0x39

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
    if op == 0x10:
        return off + code[off + 1] + 1
    if op == 0x11:
        return off + (code[off + 1] | (code[off + 2] << 8)) + 1
    if op == 0x12:
        return off - code[off + 1]
    if op == 0x13:
        return off - (code[off + 1] | (code[off + 2] << 8))
    if op == 0x14:
        return off + code[off + 5] + 5
    if op == 0x15:
        return off + (code[off + 5] | (code[off + 6] << 8)) + 5
    if op in (0x16, 0x18):
        return off + code[off + 7] + 7
    if op in (0x17, 0x19):
        return off + (code[off + 7] | (code[off + 8] << 8)) + 7
    if op in (0x30, 0x31, 0x32):
        return off + code[off + 3] + 3
    if op in (0xCB, 0xCC):
        return off + code[off + 2] + 2
    return None

def walk(code, entry, errors):
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
                if op in (0x10, 0x11, 0x12, 0x13):
                    off = t
                    continue
                stack.append(t)
            off += sz
    return seen

# -- flevel + maplist -------------------------------------------------------------
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

# -- model loader section parse (format decoded v2.16, validated live) ------------
def parse_model_labels(dec, sec_offs):
    """Ordered .char labels from the model loader (section index 2).
    Returns [] on any format surprise (caller treats field as unlabeled)."""
    base = sec_offs[2] + 4
    if base + 6 > len(dec):
        return []
    # header: u16 blank, u16 nModels, u16 scale
    n_models = struct.unpack_from('<H', dec, base + 2)[0]
    if n_models > 64:
        return []
    labels = []
    p = base + 6
    for _ in range(n_models):
        if p + 2 > len(dec):
            return []
        name_len = struct.unpack_from('<H', dec, p)[0]
        if name_len > 132 or p + 2 + name_len > len(dec):
            return []
        label = dec[p + 2:p + 2 + name_len].split(b'\0')[0] \
            .decode('ascii', 'replace').lower()
        p += 2 + name_len
        # u16 unknown, char[8] hrc, char[4] scale, u16 nAnims, 30B light
        if p + 2 + 8 + 4 + 2 + 30 > len(dec):
            return []
        n_anims = struct.unpack_from('<H', dec, p + 14)[0]
        p += 2 + 8 + 4 + 2 + 30
        # each anim: u16-len-prefixed name + u16 unknown
        for _ in range(n_anims):
            if p + 2 > len(dec):
                return []
            alen = struct.unpack_from('<H', dec, p)[0]
            if alen > 132:
                return []
            p += 2 + alen + 2
        labels.append(label if label.endswith('.char') else label)
    return labels

# -- the walk ----------------------------------------------------------------------
FLAG_LOOT, FLAG_MES, FLAG_MJUMP, FLAG_VISI = 1, 2, 4, 8

entries = []   # (field_id, entity_id, model_idx, flags)
stats = dict(fields=0, model_ents=0, talk_ents=0, loot_ents=0,
             loot_with_visi=0, walk_errors=0, label_fail=0)
detail = defaultdict(list)   # fname -> rows for printing

REACTOR_FIELDS = {'md1_1', 'md1_2', 'nmkin_1', 'nmkin_2', 'nmkin_3',
                  'nmkin_4', 'nmkin_5', 'md1stin', 'mds7st3'}

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

    labels = parse_model_labels(dec, sec_offs)
    if not labels:
        stats['label_fail'] += 1

    def slot_offs(e):
        return [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
                for s in range(32)]

    ename = lambda e: dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8] \
        .split(b'\0')[0].decode('ascii', 'replace')

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
        # line entities are the line catalog's business
        if any(op in (OP_LINE, OP_SLINE) for op in init.values()):
            continue
        # model binding: CHAR n in init
        char_off = next((o for o, op in init.items() if op == OP_CHAR), None)
        if char_off is None:
            continue
        model_idx = code[char_off + 1]
        stats['model_ents'] += 1

        talk = dict(slot_walk(e, 1, errors))
        # one-hop REQ expansion (the line catalog's rule)
        for off, op in list(talk.items()):
            if op in (OP_REQ, OP_REQSW, OP_REQEW):
                te = code[off + 1]
                ts = code[off + 2] & 0x1F
                if te < n_ent:
                    talk.update(slot_walk(te, ts, errors))
        stats['walk_errors'] += len(errors)

        ops = set(talk.values())
        if not (ops - {OP_RET}):
            continue                      # no talk behavior
        stats['talk_ents'] += 1

        flags = 0
        if OP_STITM in ops or OP_SMTRA in ops or OP_GOLDP in ops:
            flags |= FLAG_LOOT
            stats['loot_ents'] += 1
            if OP_VISI in ops:
                stats['loot_with_visi'] += 1
        if OP_MES in ops or OP_ASK in ops:
            flags |= FLAG_MES
        if OP_MJUMP in ops:
            flags |= FLAG_MJUMP
        if OP_VISI in ops:
            flags |= FLAG_VISI

        for fid2 in name_to_ids[fname]:
            entries.append((fid2, e, model_idx, flags))
        lbl = labels[model_idx] if model_idx < len(labels) else '(?)'
        detail[fname].append((e, ename(e), model_idx, lbl, flags))

entries.sort()
print(f"fields walked          : {stats['fields']}")
print(f"model-section fails    : {stats['label_fail']}")
print(f"model entities         : {stats['model_ents']}")
print(f"  with talk scripts    : {stats['talk_ents']}")
print(f"  loot-granting talks  : {stats['loot_ents']}")
print(f"  loot talks with VISI : {stats['loot_with_visi']}")
print(f"walk errors            : {stats['walk_errors']}")
if stats['loot_ents']:
    r = 100.0 * stats['loot_with_visi'] / stats['loot_ents']
    print(f"\nPICKUP HIDE MECHANISM: {r:.1f}% of loot-granting talk scripts "
          f"reach VISI (0xA4)")
    print("  -> high ratio justifies the VISI-handler byte hunt "
          "(ff7_visi_handler_disasm.py)")

print("\n=== REACTOR ROUTE + GROUND-TRUTH FIELDS ===")
for fld in sorted(REACTOR_FIELDS):
    for e, en, mi, lbl, fl in detail.get(fld, []):
        tags = [t for b, t in ((FLAG_LOOT, 'LOOT'), (FLAG_MES, 'MES'),
                               (FLAG_MJUMP, 'MJUMP'), (FLAG_VISI, 'VISI'))
                if fl & b]
        print(f"  {fld}: ent={e} '{en}' model={mi} '{lbl}' "
              f"[{' '.join(tags) or 'talk-only'}]")

# -- header generation --------------------------------------------------------------
hdr_path = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'AccessibilityMod', 'src', 'ff7_prop_catalog.h'))
with open(hdr_path, 'w', encoding='utf-8', newline='\n') as h:
    h.write(f"""// ff7_prop_catalog.h -- GENERATED by
// investigate/ff7_prop_interact_catalog.py ({datetime.date.today()}); do not
// hand-edit. Re-run the generator after any game-data change.
//
// Every MODEL entity in the game whose TALK script (slot 1) does
// something -- keyed by (maplist field id, script entity id), with the
// model-loader index the entity's init CHAR opcode binds and evidence
// flags for what the talk script reaches. The mod consults this ONLY
// for models its label classifier filed as scenery: a scenery model
// with a talk script is an interactive PROP (button, lever, valve --
// the v2.30.36 deferred whitelist), surfaced in the pathfinder instead
// of hidden. Models classified people/chests/items/saves ignore this
// table (they are already listed; one classifier, one place -- v2.18.2).
//
// stats: {stats['fields']} fields, {stats['model_ents']} model entities,
// {stats['talk_ents']} with talk scripts, {stats['loot_ents']} loot-granting
// ({stats['loot_with_visi']} of those reach VISI), {stats['walk_errors']} walk errors.
#pragma once
#include <cstdint>

namespace FF7PropCatalog {{

constexpr uint8_t PF_LOOT  = 1;  // talk grants item/materia/gil (pickup)
constexpr uint8_t PF_MES   = 2;  // talk shows a message / asks
constexpr uint8_t PF_MJUMP = 4;  // talk can change fields
constexpr uint8_t PF_VISI  = 8;  // talk toggles model visibility

struct PropInfo {{
    uint16_t field_id;
    uint8_t  entity_id;
    uint8_t  model_idx;   // model-loader index bound by init's CHAR
    uint8_t  flags;       // PF_* above
}};

// Sorted by (field_id, entity_id) for binary search.
inline constexpr PropInfo kProps[] = {{
""")
    for fid2, e, mi, fl in entries:
        h.write(f"    {{{fid2}, {e}, {mi}, {fl}}},\n")
    h.write("""};

// Find by (field, entity). Runtime gets the entity id from
// field_event_data +0x5D.
inline const PropInfo* Find(uint16_t field_id, uint8_t entity_id)
{
    size_t lo = 0, hi = sizeof(kProps) / sizeof(kProps[0]);
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        const PropInfo& p = kProps[mid];
        if (p.field_id < field_id ||
            (p.field_id == field_id && p.entity_id < entity_id))
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < sizeof(kProps) / sizeof(kProps[0]) &&
        kProps[lo].field_id == field_id && kProps[lo].entity_id == entity_id)
        return &kProps[lo];
    return nullptr;
}

} // namespace FF7PropCatalog
""")
print(f"\nHeader written: {hdr_path} ({len(entries)} entries)")
