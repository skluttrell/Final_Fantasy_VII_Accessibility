#!/usr/bin/env python3
"""
ff7_gateway_flevel_dump.py -- Game-wide offline characterization of the field
trigger section (raw section 7): gateway records and door-trigger boxes
(2026-08-02, companion to the ff7_gateway_*_disasm.py static proofs).

WHAT THE STATIC SIDE ALREADY PROVED (exe on disk):
  Gateway record (24B, hdr+0x38, 12 slots): +0x0C/+0x0E dest X/Y,
  +0x10 dest TRIANGLE, +0x12 dest field id, and **+0x14 (byte) = ARRIVAL
  DIRECTION** -- the crossing-hit path (0x636233) feeds exactly these into
  the modules-global transition interface, and the arrival code writes the
  direction into the player's field_event_data +0x38 (facing).

WHAT THIS SCRIPT ADDS (flevel.lgp, all fields, no live game):
  1. +0x15..+0x17: are the remaining three "unknown" bytes ever nonzero?
     (If always 0 -> padding; if patterned -> flags worth chasing, e.g. the
     long-suspected story-lock byte.)
  2. Game-wide validation of the +0x10 = TRIANGLE reading: the value must be
     < nTriangles of the DESTINATION field's walkmesh for (nearly) every
     used gateway. A z-coordinate would blow past triangle counts constantly.
  3. Destination-vertex sanity for two-way pairs: D(A->B) should sit near
     B's return gateway line (the "you appear just inside the exit you'd
     leave through" model).
  4. triggers[12] (hdr+0x158, 16B records: 2 corner vertices, bg_group_id,
     bg_frame_id, behavior, sound_id -- the DOOR/DEVICE boxes): how many
     fields use them, behavior-byte distribution, and full dumps for fields
     the player knows (md1stin, nmkin_1/2, elevtr1, mds7st1...). This is the
     candidate "Doors" data source for the pathfinder.

Output teed to a timestamped log (standing investigation-script rule).
"""
import sys, os, struct, datetime, math

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"gateway_flevel_dump_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# maplist: field id -> name and back (32-byte entries; nmkin_2 anchor at 122)
mo = next((o for nm, o in toc if nm == 'maplist'), None)
mlen = struct.unpack_from('<I', data, mo + 20)[0]
mraw = data[mo + 24:mo + 24 + mlen]
start = next((s for s in (0, 2)
              if mraw[s + 122 * 32:s + 123 * 32].split(b'\0')[0] == b'nmkin_2'),
             None)
if start is None:
    print("ERROR: maplist anchor failed")
    sys.exit(1)
id_to_name = {}
name_to_id = {}
fid = 0
for off in range(start, len(mraw) - 31, 32):
    nm = mraw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace').lower()
    if nm:
        id_to_name[fid] = nm
        name_to_id.setdefault(nm, fid)
    fid += 1
print(f"maplist: {fid} ids, {len(name_to_id)} named\n")

# -- parse every field: trigger section (raw index 7) + walkmesh nTri (index 4)
UNUSED = 0x7FFF
fields = {}     # name -> dict(gateways=[...], triggers=[...], ntri=int,
                #              control_dir=int)

for fname, entry_off in toc:
    if fname not in name_to_id:
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
    # walkmesh (section index 4): +4 skips the u32 section-size prefix,
    # then u32 nTriangles (format per research doc §4 walkmesh row)
    wm = sec_offs[4] + 4
    ntri = struct.unpack_from('<I', dec, wm)[0] if wm + 4 <= len(dec) else 0
    # triggers (section index 7): +4 size prefix, then the 0x2E4-byte header
    tg = sec_offs[7] + 4
    if tg + 0x2E4 > len(dec):
        continue
    hdr = dec[tg:tg + 0x2E4]
    control_dir = hdr[9]
    gws = []
    for g in range(12):
        r = hdr[0x38 + g * 24: 0x38 + (g + 1) * 24]
        v1 = struct.unpack_from('<3h', r, 0)
        v2 = struct.unpack_from('<3h', r, 6)
        dv = struct.unpack_from('<3h', r, 12)
        did = struct.unpack_from('<h', r, 18)[0]
        unk = tuple(r[20:24])
        gws.append(dict(v1=v1, v2=v2, dest=dv, field=did, unk=unk))
    trs = []
    for t in range(12):
        r = hdr[0x158 + t * 16: 0x158 + (t + 1) * 16]
        c1 = struct.unpack_from('<3h', r, 0)
        c2 = struct.unpack_from('<3h', r, 6)
        bg_group, bg_frame, behavior, sound = r[12], r[13], r[14], r[15]
        trs.append(dict(c1=c1, c2=c2, group=bg_group, frame=bg_frame,
                        behavior=behavior, sound=sound))
    fields[fname] = dict(gateways=gws, triggers=trs, ntri=ntri,
                         control_dir=control_dir)

print(f"parsed {len(fields)} fields with trigger sections\n")

# -- 1+2: gateway stats ------------------------------------------------------------
used = []
for nm, f in fields.items():
    for gi, g in enumerate(f['gateways']):
        if g['field'] != UNUSED:
            used.append((nm, gi, g))

print(f"USED GATEWAYS: {len(used)}")
from collections import Counter
u1 = Counter(g['unk'][1] for _, _, g in used)
u2 = Counter(g['unk'][2] for _, _, g in used)
u3 = Counter(g['unk'][3] for _, _, g in used)
u0 = Counter(g['unk'][0] for _, _, g in used)
print(f"  +0x14 (ARRIVAL DIR, proven): {len(u0)} distinct values, "
      f"min {min(u0)}, max {max(u0)}")
print(f"  +0x15 distribution: {dict(sorted(u1.items())) if len(u1) <= 12 else dict(u1.most_common(12))}")
print(f"  +0x16 distribution: {dict(sorted(u2.items())) if len(u2) <= 12 else dict(u2.most_common(12))}")
print(f"  +0x17 distribution: {dict(sorted(u3.items())) if len(u3) <= 12 else dict(u3.most_common(12))}")

# triangle-id validation against the DESTINATION field's walkmesh
ok = bad = noinfo = 0
bad_list = []
for nm, gi, g in used:
    dnm = id_to_name.get(g['field'])
    dest_f = fields.get(dnm) if dnm else None
    if not dest_f or dest_f['ntri'] == 0:
        noinfo += 1
        continue
    if 0 <= g['dest'][2] < dest_f['ntri']:
        ok += 1
    else:
        bad += 1
        if len(bad_list) < 15:
            bad_list.append((nm, gi, g['dest'][2], dnm, dest_f['ntri']))
print(f"\nDEST +0x10 vs destination walkmesh nTriangles: "
      f"{ok} in-range, {bad} out-of-range, {noinfo} unresolvable")
for nm, gi, tri, dnm, ntri in bad_list:
    print(f"  OUT: {nm} gw{gi} tri={tri} dest={dnm} (nTri={ntri})")

# -- 3: two-way pair check: dest vertex near the return gateway's exit line -------
def seg_dist(p, a, b):
    """2D distance from point p to segment a-b (Z ignored, walkmesh units)."""
    px, py = p[0], p[1]
    ax, ay = a[0], a[1]
    bx, by = b[0], b[1]
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy
    if L2 == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / L2))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))

pair_d = []
for nm, gi, g in used:
    dnm = id_to_name.get(g['field'])
    dest_f = fields.get(dnm) if dnm else None
    if not dest_f:
        continue
    my_id = name_to_id.get(nm)
    returns = [r for r in dest_f['gateways'] if r['field'] == my_id]
    if not returns:
        continue
    d = min(seg_dist(g['dest'], r['v1'], r['v2']) for r in returns)
    pair_d.append(d)
if pair_d:
    pair_d.sort()
    n = len(pair_d)
    print(f"\nTWO-WAY PAIRS: {n} gateways have a return gateway in the dest field")
    print(f"  dest-vertex distance to return exit line (walkmesh units):")
    print(f"  median {pair_d[n//2]:.0f}, p90 {pair_d[int(n*0.9)]:.0f}, max {pair_d[-1]:.0f}")

# -- 4: door-trigger boxes ---------------------------------------------------------
def trig_used(t):
    # A slot is unused when both corners are all-zero (observed convention;
    # a real box has nonzero extent somewhere).
    return any(t['c1']) or any(t['c2'])

tr_fields = 0
tr_total = 0
beh = Counter()
snd = Counter()
for nm, f in fields.items():
    us = [t for t in f['triggers'] if trig_used(t)]
    if us:
        tr_fields += 1
        tr_total += len(us)
        for t in us:
            beh[t['behavior']] += 1
            snd[t['sound']] += 1
print(f"\nDOOR/DEVICE TRIGGER BOXES (hdr+0x158): {tr_total} used slots across "
      f"{tr_fields}/{len(fields)} fields")
print(f"  behavior byte distribution: {dict(sorted(beh.items()))}")
print(f"  sound id nonzero count: {sum(c for s, c in snd.items() if s != 0)}"
      f" (distinct ids: {len([s for s in snd if s != 0])})")

# -- spot dumps for fields the player has walked ----------------------------------
SPOT = ['md1stin', 'md1_1', 'md1_2', 'nmkin_1', 'nmkin_2', 'elevtr1',
        'mds7st1', 'mds7st2', 'mds7', '4sbwy_1']
for nm in SPOT:
    f = fields.get(nm)
    if not f:
        continue
    print(f"\n=== {nm} (id {name_to_id.get(nm)}, control_dir {f['control_dir']}, "
          f"nTri {f['ntri']}) ===")
    for gi, g in enumerate(f['gateways']):
        if g['field'] == UNUSED:
            continue
        dnm = id_to_name.get(g['field'], '?')
        deg = g['unk'][0] * 360.0 / 256.0
        print(f"  gw{gi}: exit ({g['v1'][0]},{g['v1'][1]})-({g['v2'][0]},{g['v2'][1]})"
              f" -> {dnm}({g['field']}) at ({g['dest'][0]},{g['dest'][1]})"
              f" tri {g['dest'][2]}, arrive dir {g['unk'][0]} ({deg:.0f} deg),"
              f" unk15/16/17={g['unk'][1]}/{g['unk'][2]}/{g['unk'][3]}")
    for ti, t in enumerate(f['triggers']):
        if not trig_used(t):
            continue
        print(f"  door{ti}: box ({t['c1'][0]},{t['c1'][1]},{t['c1'][2]})-"
              f"({t['c2'][0]},{t['c2'][1]},{t['c2'][2]}) bg_group {t['group']}"
              f" frame {t['frame']} behavior {t['behavior']} sound {t['sound']}")

print(f"\nLog saved to: {_log_path}")
