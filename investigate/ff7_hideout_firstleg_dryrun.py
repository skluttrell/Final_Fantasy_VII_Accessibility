#!/usr/bin/env python3
"""
ff7_hideout_firstleg_dryrun.py -- OFFLINE reproduction of the 2026-07-25
play report: "Pathfinder tells me to get to Barret I need to go left 1
second then down and left 1 second, but if I try to go left I get the wall
sound." (7th Heaven hideout, field id 155.)

Log ground truth (ffvii_accessibility.log 10:01:34-10:04:56):
  NAV dir Barret line=(-209,117)-(-209,117) player=(29,31)
      dist=253 world_deg=-70.1 ctrl=96 dir=down and left
  NAV walkmesh: 7 edge(s) cut by triangle locks
  NAV route tris=78 start=42 goal=35 path=10 corners=4
      'left 1 second, then down and left 1 second'

WHY OFFLINE (method playbook #3): the walkmesh in FIELD_FILE_BUFFER is the
decompressed field file from flevel.lgp -- parsing the file on disk IS
parsing what the mod read live. Replicating the exact shipped pipeline
(A* -> portals -> funnel -> speech, v2.30.21 lock overlay included) over
that data reproduces the exact spoken route, and then lets us interrogate
the geometry the player cannot see: where does a player standing at
(29,31) actually END UP when they hold "left"? How far before the mesh
edge stops them? Was the first leg even followable?

WHAT IT DOES:
  1. maplist: resolve field id 155 -> internal field name.
  2. Parse that field's walkmesh (section 4) + control_direction
     (triggers section 7, +9) -- expect ctrl=96 -> 135.0 deg.
  3. Extract IDLCK (opcode 0x6D: u16 triangle + u8 flag) candidates from
     the script section byte stream; find the lock set + flag polarity
     whose edge-cut count matches the log's "7 edge(s) cut".
  4. Replicate the route EXACTLY (same A*, portals, funnel, fold
     constants, sector quantization as proxy.cpp) -- must reproduce
     path=10 corners=4 and the exact spoken text before any conclusions.
  5. Diagnose: per-leg exact bearings vs the quantized sector centers;
     walk-simulate from (29,31) along (a) the exact first-leg bearing and
     (b) the quantized "left" sector center, stepping across the lock-cut
     adjacency graph the way the game's own edge-crossing code does, and
     report the distance at which each ray gets stopped by a wall/lock.
     Also report closest approach to Tifa (29,95) -- model collision is
     indistinguishable from a wall to the bump tone.
"""
import sys, os, struct, math, datetime, heapq

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"hideout_firstleg_dryrun_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- session ground truth from the live log --------------------------------------
FIELD_ID   = 155
START_TRI  = 42
GOAL_TRI   = 35
PLAYER     = (29.0, 31.0)
TARGET     = (-209.0, 117.0)     # Barret's model position (the route target)
TIFA       = (29.0, 95.0)        # nearby NPC -- collision suspect
EXPECT_CTRL = 96                 # -> 135.0 deg
EXPECT_CUTS = 7                  # log: "7 edge(s) cut by triangle locks"
EXPECT_PATH = 10
EXPECT_CORNERS = 4
EXPECT_SPEECH = "left 1 second, then down and left 1 second"

# -- locate flevel.lgp -----------------------------------------------------------
CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found in either install.")
    sys.exit(1)
print(f"Reading: {lgp_path}")
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = {}
for i in range(n_files):
    off = 16 + i * 27
    raw_name = data[off:off + 20].split(b'\0')[0]
    file_off = struct.unpack_from('<I', data, off + 20)[0]
    toc[raw_name.decode('ascii', 'replace').lower()] = file_off
print(f"TOC: {n_files} files\n")

# -- 1. maplist: field id -> name ------------------------------------------------
# 32-byte zero-padded ASCII names; ff7_maplist_catalog.py validated the
# format with a possible u16 count prefix. Anchor: the generated
# ff7_field_names.h has 155 = "mds7pb_2"; whichever start offset
# reproduces that (and 122 = "nmkin_2") is the right one.
mo = toc.get('maplist')
if mo is None:
    print("ERROR: maplist missing from TOC")
    sys.exit(1)
mlen = struct.unpack_from('<I', data, mo + 20)[0]
mraw = data[mo + 24:mo + 24 + mlen]
ENTRY = 32
_names_start = None
for _start in (0, 2):
    probe = mraw[_start + 122 * ENTRY:_start + 123 * ENTRY].split(b'\0')[0]
    if probe == b'nmkin_2':
        _names_start = _start
        break
if _names_start is None:
    print("ERROR: maplist anchor nmkin_2@122 failed at both start offsets")
    sys.exit(1)
def map_name(fid):
    off = _names_start + fid * ENTRY
    return mraw[off:off + ENTRY].split(b'\0')[0].decode('ascii', 'replace')
print("maplist around field 155:")
for fid in range(150, 158):
    mark = "  <-- this session" if fid == FIELD_ID else ""
    print(f"  {fid}: {map_name(fid)!r}{mark}")
field_name = map_name(FIELD_ID).lower()
if not field_name:
    print("ERROR: empty maplist entry for 155")
    sys.exit(1)

# -- 2. parse the field file -----------------------------------------------------
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

entry_off = toc.get(field_name)
if entry_off is None:
    print(f"ERROR: field file {field_name!r} not in TOC")
    sys.exit(1)
flen = struct.unpack_from('<I', data, entry_off + 20)[0]
raw = data[entry_off + 24:entry_off + 24 + flen]
comp = raw[4:]
# Decompress the WHOLE file: we need script (sec 0), walkmesh (4),
# triggers (7). Field files are < 2 MB decompressed.
dec = lzs_decompress(comp, 4 * 1024 * 1024)
sec_offs = struct.unpack_from('<9I', dec, 6)
print(f"\nfield {field_name!r}: {len(dec)} bytes decompressed, "
      f"sections at {[hex(o) for o in sec_offs]}")

WALKMESH_IDX, TRIGGERS_IDX, SCRIPT_IDX = 4, 7, 0
TRI_SIZE, ACC_SIZE = 24, 6
NO_NBR = 0xFFFF

wm_off = sec_offs[WALKMESH_IDX]
sec_size, ntris = struct.unpack_from('<II', dec, wm_off)
print(f"walkmesh: ntris={ntris} (log said tris=78)")
tris = []
tbase = wm_off + 8
abase = tbase + ntris * TRI_SIZE
for t in range(ntris):
    v = struct.unpack_from('<12h', dec, tbase + t * TRI_SIZE)
    a = struct.unpack_from('<3H', dec, abase + t * ACC_SIZE)
    tris.append([(v[0], v[4], v[8]), (v[1], v[5], v[9]), list(a),
                 (v[2], v[6], v[10])])
ctrl = dec[sec_offs[TRIGGERS_IDX] + 4 + 9]
control_deg = ctrl * 360.0 / 256.0
print(f"control_direction: {ctrl} -> {control_deg:.1f} deg "
      f"(log said ctrl=96 -> 135.0)")

# -- 3. IDLCK lock set -----------------------------------------------------------
# Scan the script section's byte stream for the IDLCK pattern:
#   6D <u16 triangle> <u8 flag>, triangle < ntris, flag in {0,1}.
# A raw byte scan over script code has false-positive risk (0x6D can be an
# operand), so every candidate is listed, then the lock SET is chosen by
# matching the mod's own runtime observation: exactly 7 directed edges cut.
sc_lo, sc_hi = sec_offs[SCRIPT_IDX] + 4, sec_offs[1]
cands = []
for off in range(sc_lo, sc_hi - 4):
    if dec[off] != 0x6D:
        continue
    tri = struct.unpack_from('<H', dec, off + 1)[0]
    flag = dec[off + 3]
    if tri < ntris and flag in (0, 1):
        cands.append((off, tri, flag))
print(f"\nIDLCK byte-pattern candidates in script section: {len(cands)}")
for off, tri, flag in cands:
    print(f"  @0x{off:05X}  tri={tri:<3d} flag={flag}")

def count_cuts(lock_set):
    cuts = 0
    for t in range(ntris):
        for nb in tris[t][2]:
            if nb != NO_NBR and nb in lock_set:
                cuts += 1
    return cuts

# Try both flag polarities (docs don't fix which value means "lock");
# report every candidate set's cut count and pick the one matching 7.
sets = {
    "flag==0 locks": {tri for _, tri, f in cands if f == 0},
    "flag==1 locks": {tri for _, tri, f in cands if f == 1},
    "all mentioned":  {tri for _, tri, _ in cands},
}
lock_set = None
for label, s in sets.items():
    c = count_cuts(s)
    match = "  <== matches log (7 cuts)" if c == EXPECT_CUTS else ""
    print(f"  {label}: tris={sorted(s)} cuts={c}{match}")
    if c == EXPECT_CUTS and lock_set is None:
        lock_set = s
if lock_set is None:
    print("WARNING: no polarity reproduces 7 cuts -- proceeding UNLOCKED; "
          "route reproduction below will say whether locks matter here.")
    lock_set = set()

# Apply the v2.30.21 overlay: cut every edge INTO a locked triangle.
for t in range(ntris):
    tris[t][2] = [NO_NBR if (nb != NO_NBR and nb in lock_set) else nb
                  for nb in tris[t][2]]

# -- 4. exact pipeline replica ---------------------------------------------------
KDPAD = ["up", "up and right", "right", "down and right",
         "down", "down and left", "left", "up and left"]
UNITS_PER_SEC = 160.0
MIN_SEG = 120.0
MAX_SPOKEN = 5

def sector_index(deg):
    norm = math.fmod(deg + 22.5, 360.0)
    if norm < 0:
        norm += 360.0
    return min(7, max(0, int(norm / 45.0)))

def centroid(t):
    return (sum(tris[t][0]) / 3.0, sum(tris[t][1]) / 3.0)

def astar(start, goal):
    cents = [centroid(t) for t in range(ntris)]
    def h(t):
        return math.dist(cents[t], cents[goal])
    g = {start: 0.0}
    parent = {start: -1}
    pq = [(h(start), start)]
    closed = set()
    while pq:
        _, cur = heapq.heappop(pq)
        if cur in closed:
            continue
        if cur == goal:
            path = []
            while cur != -1:
                path.append(cur)
                cur = parent[cur]
            return path[::-1]
        closed.add(cur)
        for nb in tris[cur][2]:
            if nb == NO_NBR or nb in closed:
                continue
            ng = g[cur] + math.dist(cents[cur], cents[nb])
            if ng < g.get(nb, float('inf')):
                g[nb] = ng
                parent[nb] = cur
                heapq.heappush(pq, (ng + h(nb), nb))
    return None

def tri2(ax, ay, bx, by, cx, cy):
    return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)

def build_portals(path):
    portals = []
    for i in range(len(path) - 1):
        A, B = tris[path[i]], tris[path[i + 1]]
        acx, acy = centroid(path[i])
        bcx, bcy = centroid(path[i + 1])
        shared = []
        for a in range(3):
            pt = (A[0][a], A[1][a])
            if len(shared) == 1 and shared[0] == pt:
                continue
            for b in range(3):
                if pt == (B[0][b], B[1][b]):
                    shared.append(pt)
                    break
            if len(shared) == 2:
                break
        if len(shared) == 2:
            side = tri2(acx, acy, bcx, bcy, shared[0][0], shared[0][1])
            l, r = (shared[0], shared[1]) if side >= 0 else (shared[1], shared[0])
            portals.append((l, r))
        else:
            portals.append(((bcx, bcy), (bcx, bcy)))
    return portals

def funnel(sx, sy, ex, ey, portals):
    p = list(portals) + [((ex, ey), (ex, ey))]
    corners = []
    ax, ay = sx, sy
    (lx, ly), (rx, ry) = p[0]
    li = ri = 0
    guard = len(p) * 16 + 64
    i = 1
    while i < len(p):
        guard -= 1
        if guard < 0:
            return None
        (nlx, nly), (nrx, nry) = p[i]
        if tri2(ax, ay, rx, ry, nrx, nry) >= 0.0:
            if (ax == rx and ay == ry) or tri2(ax, ay, lx, ly, nrx, nry) < 0.0:
                rx, ry, ri = nrx, nry, i
            else:
                corners.append((lx, ly))
                ax, ay = lx, ly
                lx = rx = ax; ly = ry = ay
                ri = li
                i = li + 1
                continue
        if tri2(ax, ay, lx, ly, nlx, nly) <= 0.0:
            if (ax == lx and ay == ly) or tri2(ax, ay, rx, ry, nlx, nly) > 0.0:
                lx, ly, li = nlx, nly, i
            else:
                corners.append((rx, ry))
                ax, ay = rx, ry
                lx = rx = ax; ly = ry = ay
                li = ri
                i = ri + 1
                continue
        i += 1
    corners.append((ex, ey))
    return corners

def route_to_speech(sx, sy, corners):
    segs = []
    cx, cy = sx, sy
    for (x, y) in corners:
        dx, dy = x - cx, y - cy
        ln = math.hypot(dx, dy)
        cx, cy = x, y
        if ln < 1.0:
            continue
        world = math.degrees(math.atan2(dx, dy))
        sec = sector_index(world + control_deg - 180.0)
        if segs and segs[-1][0] == sec:
            segs[-1][1] += ln
        else:
            segs.append([sec, ln])
    folded = []
    for sec, ln in segs:
        if folded and (ln < MIN_SEG or folded[-1][0] == sec):
            folded[-1][1] += ln
        else:
            folded.append([sec, ln])
    total = sum(ln for _, ln in folded)
    if total < UNITS_PER_SEC * 0.5:
        return "very close", segs, folded
    parts = []
    for sec, ln in folded[:MAX_SPOKEN]:
        s = max(1, int(ln / UNITS_PER_SEC + 0.5))
        parts.append(f"{KDPAD[sec]} {s} second{'s' if s != 1 else ''}")
    text = ", then ".join(parts)
    if len(folded) > MAX_SPOKEN:
        text += ", and more after that"
    return text, segs, folded

print("\n=== ROUTE REPRODUCTION " + "=" * 50)
path = astar(START_TRI, GOAL_TRI)
if path is None:
    print("A*: NO PATH -- does not match the log (path=10). STOP.")
    sys.exit(1)
print(f"A* path ({len(path)} tris, log said {EXPECT_PATH}): {path}")
portals = build_portals(path)
corners = funnel(PLAYER[0], PLAYER[1], TARGET[0], TARGET[1], portals)
if corners is None:
    corners = [((l[0] + r[0]) / 2.0, (l[1] + r[1]) / 2.0) for l, r in portals]
    corners.append(TARGET)
    print("funnel guard TRIPPED -> portal midpoints (log corners=4 suggests "
          "it did NOT trip live; mismatch would be a finding)")
print(f"corners ({len(corners)}, log said {EXPECT_CORNERS}): "
      f"{[(round(x,1), round(y,1)) for x, y in corners]}")
speech, segs, folded = route_to_speech(PLAYER[0], PLAYER[1], corners)
print(f"spoken: '{speech}'")
print(f"log   : '{EXPECT_SPEECH}'")
print("REPRODUCTION: " + ("EXACT MATCH" if speech == EXPECT_SPEECH
                          else "MISMATCH -- investigate before trusting "
                               "the geometry below"))

# -- 5. diagnosis ----------------------------------------------------------------
print("\n=== LEG GEOMETRY " + "=" * 56)
cx, cy = PLAYER
for i, (x, y) in enumerate(corners):
    dx, dy = x - cx, y - cy
    ln = math.hypot(dx, dy)
    if ln < 1.0:
        cx, cy = x, y
        continue
    world = math.degrees(math.atan2(dx, dy))
    inp = math.fmod(world + control_deg - 180.0 + 720.0, 360.0)
    sec = sector_index(world + control_deg - 180.0)
    off_center = ((inp - sec * 45.0 + 180.0) % 360.0) - 180.0
    print(f"  leg {i}: ({cx:6.1f},{cy:6.1f}) -> ({x:6.1f},{y:6.1f})  "
          f"len={ln:6.1f}  world={world:7.1f}  input={inp:6.1f}  "
          f"sector='{KDPAD[sec]}' (center {sec*45}, off by {off_center:+.1f} deg)")
    cx, cy = x, y
print(f"  raw segs   : {[(KDPAD[s], round(l,1)) for s, l in segs]}")
print(f"  folded segs: {[(KDPAD[s], round(l,1)) for s, l in folded]}")

# Walk simulation over the lock-cut graph: step a point along a fixed
# world-space bearing; a step that leaves the current triangle may only
# continue into a (still-linked) neighbor that contains the new point --
# the same destination-side test the game's edge-crossing code performs.
def inside(t, x, y, eps=0.5):
    vx, vy = tris[t][0], tris[t][1]
    s0 = tri2(vx[0], vy[0], vx[1], vy[1], x, y)
    s1 = tri2(vx[1], vy[1], vx[2], vy[2], x, y)
    s2 = tri2(vx[2], vy[2], vx[0], vy[0], x, y)
    return ((s0 >= -eps and s1 >= -eps and s2 >= -eps) or
            (s0 <= eps and s1 <= eps and s2 <= eps))

def walk_sim(x, y, start_tri, world_bearing_deg, max_dist=400.0, step=1.0):
    """Distance the game lets you travel from (x,y) on start_tri along a
    fixed bearing before no walkable triangle contains the next point.
    Returns (distance, stopping_triangle)."""
    dx = math.sin(math.radians(world_bearing_deg))
    dy = math.cos(math.radians(world_bearing_deg))
    cur = start_tri
    d = 0.0
    while d < max_dist:
        nx, ny = x + dx * step, y + dy * step
        if inside(cur, nx, ny):
            x, y, d = nx, ny, d + step
            continue
        moved = False
        # BFS over currently-linked neighbors (2 hops -- steps can clip a
        # vertex where >2 triangles meet).
        frontier = [nb for nb in tris[cur][2] if nb != NO_NBR]
        second = set()
        for nb in frontier:
            second.update(n2 for n2 in tris[nb][2] if n2 != NO_NBR)
        for cand in frontier + sorted(second - set(frontier) - {cur}):
            if inside(cand, nx, ny):
                cur = cand
                x, y, d = nx, ny, d + step
                moved = True
                break
        if not moved:
            return d, cur, (x, y)
    return d, cur, (x, y)

print("\n=== WALK SIMULATION from player (29,31), tri 42 " + "=" * 25)
first_leg_world = math.degrees(math.atan2(corners[0][0] - PLAYER[0],
                                          corners[0][1] - PLAYER[1]))
tests = [
    ("exact bearing to corner 1", first_leg_world),
    ("quantized 'left' (input 270)", 270.0 - control_deg + 180.0),
    ("quantized 'down and left' (input 225)", 225.0 - control_deg + 180.0),
    ("quantized 'up and left' (input 315)", 315.0 - control_deg + 180.0),
    ("straight line to Barret", math.degrees(math.atan2(
        TARGET[0] - PLAYER[0], TARGET[1] - PLAYER[1]))),
]
for label, wdeg in tests:
    dist, stop_tri, (ex, ey) = walk_sim(PLAYER[0], PLAYER[1], START_TRI, wdeg)
    secs = dist / UNITS_PER_SEC
    print(f"  {label:38s} world={wdeg:7.1f}  travels {dist:6.1f} units "
          f"({secs:4.2f}s) -> stops on tri {stop_tri} at ({ex:.0f},{ey:.0f})")

# Closest approach to Tifa along the quantized-left ray (model collision
# is indistinguishable from a wall to the player's ear).
dxl = math.sin(math.radians(270.0 - control_deg + 180.0))
dyl = math.cos(math.radians(270.0 - control_deg + 180.0))
best = 1e9
for i in range(0, 401):
    px, py = PLAYER[0] + dxl * i * 0.5, PLAYER[1] + dyl * i * 0.5
    best = min(best, math.hypot(px - TIFA[0], py - TIFA[1]))
print(f"\n  closest approach of the 'left' ray to Tifa (29,95): {best:.1f} units")

# -- corridor dump: the mesh around the route start ------------------------------
print("\n=== START-AREA MESH (path tris + their neighbors) " + "=" * 22)
show = []
seen = set()
for t in path[:5]:
    if t not in seen:
        show.append(t); seen.add(t)
    for nb in tris[t][2]:
        if nb != NO_NBR and nb not in seen:
            show.append(nb); seen.add(nb)
for t in show:
    vx, vy = tris[t][0], tris[t][1]
    nbrs = []
    for e in range(3):
        nb = tris[t][2][e]
        a, b = e, (e + 1) % 3
        tag = "WALL" if nb == NO_NBR else f"{nb}"
        if nb == NO_NBR:
            # was this edge a lock cut? re-check against the raw pool
            rawnb = struct.unpack_from('<3H', dec, abase + t * ACC_SIZE)[e]
            if rawnb != NO_NBR and rawnb in lock_set:
                tag = f"LOCKCUT({rawnb})"
        nbrs.append(f"({vx[a]},{vy[a]})-({vx[b]},{vy[b]}):{tag}")
    onpath = " *PATH*" if t in path else ""
    locked = " *LOCKED*" if t in lock_set else ""
    print(f"  tri {t:3d}{onpath}{locked}  " + "  ".join(nbrs))

# ================================================================================
# FIX EXPERIMENTS -- prototype candidate v2.30.22 changes offline and judge
# them by the only test that matters: can a walker that is limited to the 8
# quantized d-pad directions, blocked by walls AND by solid NPC bodies,
# actually follow the spoken instructions to Barret's talk radius?
# ================================================================================
PLAYER_R = 24.0        # collision radii: unverified exact values -- FF7 field
NPC_R    = 24.0        # models commonly use ~24; sensitivity checked below
TALK_R   = 70.0        # Barret's talk radius (log: talk=70)
SOLID_NPCS = [("Tifa", 29.0, 95.0)]   # solid people near this route
                                       # (Barret himself is the TARGET --
                                       # excluded; marine/camera are far)

def blocked_by_npc(x, y, rr=None):
    rr = (PLAYER_R + NPC_R) if rr is None else rr
    return any(math.hypot(x - nx, y - ny) < rr for _, nx, ny in SOLID_NPCS)

def walk_sim2(x, y, start_tri, world_bearing_deg, max_dist=400.0, step=1.0,
              npc=True):
    """walk_sim + solid-NPC circles."""
    dx = math.sin(math.radians(world_bearing_deg))
    dy = math.cos(math.radians(world_bearing_deg))
    cur = start_tri
    d = 0.0
    while d < max_dist:
        nx, ny = x + dx * step, y + dy * step
        if npc and blocked_by_npc(nx, ny):
            return d, cur, (x, y), "NPC"
        if inside(cur, nx, ny):
            x, y, d = nx, ny, d + step
            continue
        moved = False
        frontier = [nb for nb in tris[cur][2] if nb != NO_NBR]
        second = set()
        for nb in frontier:
            second.update(n2 for n2 in tris[nb][2] if n2 != NO_NBR)
        for cand in frontier + sorted(second - set(frontier) - {cur}):
            if inside(cand, nx, ny):
                cur = cand
                x, y, d = nx, ny, d + step
                moved = True
                break
        if not moved:
            return d, cur, (x, y), "WALL"
    return d, cur, (x, y), "OK"

def leg_check(sx, sy, start_tri, corners, label):
    """Follow the SPOKEN route: for each leg, walk the QUANTIZED sector
    direction for the leg's length (what an 8-way player actually does).
    Report where reality diverges."""
    print(f"\n  -- quantized-following check: {label}")
    x, y, cur = sx, sy, start_tri
    cx, cy = sx, sy
    ok = True
    for i, (tx, ty) in enumerate(corners):
        dx, dy = tx - cx, ty - cy
        ln = math.hypot(dx, dy)
        cx, cy = tx, ty
        if ln < 1.0:
            continue
        world = math.degrees(math.atan2(dx, dy))
        sec = sector_index(world + control_deg - 180.0)
        qworld = sec * 45.0 - control_deg + 180.0
        d, cur, (x, y), why = walk_sim2(x, y, cur, qworld, max_dist=ln)
        gap = math.hypot(x - tx, y - ty)
        status = "reached" if why == "OK" else f"BLOCKED by {why} at {d:.0f}u"
        print(f"     leg {i} '{KDPAD[sec]}' want {ln:.0f}u: {status}; "
              f"ends ({x:.0f},{y:.0f}), {gap:.0f}u from corner")
        if why != "OK":
            ok = False
    end_gap = math.hypot(x - TARGET[0], y - TARGET[1])
    verdict = "IN TALK RANGE" if end_gap <= TALK_R else "OUT OF RANGE"
    print(f"     final: {end_gap:.0f}u from Barret ({verdict})")
    return ok, end_gap

print("\n=== BASELINE quantized-following (shipped v2.30.21 route) " + "=" * 14)
leg_check(PLAYER[0], PLAYER[1], START_TRI, corners, "shipped route")

# -- Experiment 1: NPC-proximity penalty in A* -----------------------------------
# Add a cost penalty when an edge crossing lands near a solid NPC: the
# midpoint of the crossed portal OR the destination centroid within
# (PLAYER_R + NPC_R + margin) of an NPC costs +PENALTY. Routes then prefer
# corridors that a body isn't standing in, without ever making a region
# unreachable (penalty, not lock).
def astar_npc(start, goal, penalty=400.0, margin=12.0):
    cents = [centroid(t) for t in range(ntris)]
    rr = PLAYER_R + NPC_R + margin
    def h(t):
        return math.dist(cents[t], cents[goal])
    g = {start: 0.0}
    parent = {start: -1}
    pq = [(h(start), start)]
    closed = set()
    while pq:
        _, cur = heapq.heappop(pq)
        if cur in closed:
            continue
        if cur == goal:
            path = []
            while cur != -1:
                path.append(cur)
                cur = parent[cur]
            return path[::-1]
        closed.add(cur)
        for nb in tris[cur][2]:
            if nb == NO_NBR or nb in closed:
                continue
            ng = g[cur] + math.dist(cents[cur], cents[nb])
            if any(math.hypot(cents[nb][0] - nx, cents[nb][1] - ny) < rr
                   for _, nx, ny in SOLID_NPCS):
                ng += penalty
            if ng < g.get(nb, float('inf')):
                g[nb] = ng
                parent[nb] = cur
                heapq.heappush(pq, (ng + h(nb), nb))
    return None

print("\n=== EXPERIMENT 1: NPC-penalty A* " + "=" * 40)
path1 = astar_npc(START_TRI, GOAL_TRI)
print(f"  path ({len(path1)} tris): {path1}")
if path1 != path:
    c1 = funnel(PLAYER[0], PLAYER[1], TARGET[0], TARGET[1], build_portals(path1))
    if c1 is None:
        print("  funnel guard tripped")
    else:
        s1, _, _ = route_to_speech(PLAYER[0], PLAYER[1], c1)
        print(f"  corners: {[(round(x,1), round(y,1)) for x, y in c1]}")
        print(f"  spoken : '{s1}'")
        leg_check(PLAYER[0], PLAYER[1], START_TRI, c1, "NPC-penalty route")
else:
    print("  same path as baseline -- penalty changed nothing here")

# -- Experiment 2: portal inset (agent radius) -----------------------------------
# Pull each portal endpoint toward the portal's other end by INSET units
# (half-width capped) before funneling: corners stop sitting exactly ON
# wall vertices, so quantized directions get breathing room.
def inset_portals(portals, inset):
    out = []
    for (lx, ly), (rx, ry) in portals:
        ex, ey = rx - lx, ry - ly
        w = math.hypot(ex, ey)
        if w > 2.0 * inset:
            ux, uy = ex / w, ey / w
            out.append(((lx + ux * inset, ly + uy * inset),
                        (rx - ux * inset, ry - uy * inset)))
        elif w > 1e-6:
            mx, my = (lx + rx) / 2.0, (ly + ry) / 2.0
            out.append(((mx, my), (mx, my)))
        else:
            out.append(((lx, ly), (rx, ry)))
    return out

for INSET in (20.0, 28.0):
    print(f"\n=== EXPERIMENT 2: portal inset {INSET:.0f}u " + "=" * 38)
    c2 = funnel(PLAYER[0], PLAYER[1], TARGET[0], TARGET[1],
                inset_portals(portals, INSET))
    if c2 is None:
        print("  funnel guard tripped")
        continue
    s2, _, _ = route_to_speech(PLAYER[0], PLAYER[1], c2)
    print(f"  corners: {[(round(x,1), round(y,1)) for x, y in c2]}")
    print(f"  spoken : '{s2}'")
    leg_check(PLAYER[0], PLAYER[1], START_TRI, c2, f"inset {INSET:.0f}")

# -- Experiment 3: both ----------------------------------------------------------
print("\n=== EXPERIMENT 3: NPC-penalty A* + portal inset 20u " + "=" * 20)
if path1:
    c3 = funnel(PLAYER[0], PLAYER[1], TARGET[0], TARGET[1],
                inset_portals(build_portals(path1), 20.0))
    if c3 is None:
        print("  funnel guard tripped")
    else:
        s3, _, _ = route_to_speech(PLAYER[0], PLAYER[1], c3)
        print(f"  corners: {[(round(x,1), round(y,1)) for x, y in c3]}")
        print(f"  spoken : '{s3}'")
        leg_check(PLAYER[0], PLAYER[1], START_TRI, c3, "combined")

# ================================================================================
# EXPERIMENT 4: post-funnel NPC-circle detours + realistic follow model.
#
# Reality checks applied to the judge:
#   - the game SLIDES along walls (the 09:46/10:01 calib lines show deflected
#     motion_deg while a direction was held against geometry) -- so the sim
#     slides on walls; NPC bodies HARD-STOP (the live report: player parked at
#     (29,31) for minutes with the bump tone).
#   - a real player re-queries K en route -- so the judge re-runs the full
#     pipeline from wherever the previous first leg actually ended, following
#     only the FIRST spoken leg per query (worst-case usage).
#   - ALL solid people in the room count, not just Tifa: the ava* trio
#     (Biggs/Wedge/Jessie) stand in the lower half (log positions).
# ================================================================================
SOLID_NPCS = [("Tifa",   29.0,   95.0),
              ("avaman", -191.0,  46.0),
              ("avafat", -16.0, -136.0),
              ("avawoman", 130.0, 40.0),
              ("marine",  -89.0, 229.0)]
# RADIUS EVIDENCE (this session's log): the player came to rest at EXACTLY
# 64.0 units from Tifa and could not move any direction with a positive
# component toward her. 64 = 32 + 32 -- the classic FF7 0x20 collision
# radius on both models. All experiments below use 32/32.
PLAYER_R = 32.0
NPC_R    = 32.0
CLEAR_R  = PLAYER_R + NPC_R + 6.0   # detection ring (hard block at 64)

def seg_hits_circle(x1, y1, x2, y2, cx, cy, r):
    return PointSegDist2(x1, y1, x2, y2, cx, cy) < r * r

def PointSegDist2(x1, y1, x2, y2, px, py):
    ex, ey = x2 - x1, y2 - y1
    l2 = ex * ex + ey * ey
    t = 0.0 if l2 <= 0 else max(0.0, min(1.0, ((px - x1) * ex + (py - y1) * ey) / l2))
    dx, dy = x1 + t * ex - px, y1 + t * ey - py
    return dx * dx + dy * dy

def in_mesh(x, y):
    return any(inside(t, x, y, eps=0.5) for t in range(ntris))

def wall_clearance(x, y):
    """Distance to the nearest WALL edge (post-lock adjacency)."""
    best = 1e9
    for t in range(ntris):
        vx, vy = tris[t][0], tris[t][1]
        for e in range(3):
            if tris[t][2][e] == NO_NBR:
                a, b = e, (e + 1) % 3
                best = min(best, math.sqrt(
                    PointSegDist2(vx[a], vy[a], vx[b], vy[b], x, y)))
    return best

def bypass_points(px, py, qx, qy, ox, oy, R):
    """Arc bypass of circle (O,R) for segment P->Q: sample the circle at
    16 angles; the two candidate paths are the CW and CCW arcs between
    P's and Q's angular positions (exclusive). Returns {dir: [pts]} for
    directions whose every waypoint is in-mesh with wall clearance."""
    N = 16
    aP = math.atan2(py - oy, px - ox)
    aQ = math.atan2(qy - oy, qx - ox)
    res = {}
    for direction in (+1, -1):
        # sweep from aP toward aQ in this rotation direction
        sweep = (aQ - aP) * direction % (2.0 * math.pi)
        steps = max(1, int(sweep / (2.0 * math.pi) * N))
        pts = []
        ok = True
        for k in range(1, steps + 1):
            a = aP + direction * sweep * k / (steps + 1)
            x, y = ox + R * math.cos(a), oy + R * math.sin(a)
            if not (in_mesh(x, y) and wall_clearance(x, y) > 18.0):
                ok = False
                break
            pts.append((x, y))
        if ok and pts:
            res[direction] = pts
    return res

def insert_npc_detours(sx, sy, corners, targets_excluded, R=CLEAR_R + 7.0):
    """Iteratively reroute route legs around solid-NPC clearance circles
    using tangent-arc bypasses (validated in-mesh). Up to 3 passes so the
    inserted sub-legs get re-checked against OTHER bodies."""
    pts = list(corners)
    for _ in range(3):
        changed = False
        out = []
        px, py = sx, sy
        for (x, y) in pts:
            hit = None
            for name, nx, ny in SOLID_NPCS:
                if name in targets_excluded:
                    continue
                if seg_hits_circle(px, py, x, y, nx, ny, CLEAR_R):
                    hit = (nx, ny)
                    break
            if hit is not None and math.hypot(x - px, y - py) >= 1.0:
                options = bypass_points(px, py, x, y, hit[0], hit[1], R)
                if options:
                    # prefer the side with the shorter added path
                    def added(pl):
                        tot, ax, ay = 0.0, px, py
                        for (bx, by) in pl + [(x, y)]:
                            tot += math.hypot(bx - ax, by - ay)
                            ax, ay = bx, by
                        return tot
                    side = min(options, key=lambda s: added(options[s]))
                    out.extend(options[side])
                    changed = True
            out.append((x, y))
            px, py = x, y
        pts = out
        if not changed:
            break
    return pts

def walk_sim3(x, y, world_bearing_deg, max_dist, step=1.0):
    """Slide-on-walls, hard-stop-on-NPCs walker. Returns (dist_along_
    request, endpoint, why)."""
    hdx = math.sin(math.radians(world_bearing_deg))
    hdy = math.cos(math.radians(world_bearing_deg))
    cur = None
    for t in range(ntris):
        if inside(t, x, y):
            cur = t
            break
    if cur is None:
        return 0.0, (x, y), "OFFMESH"
    d = 0.0
    stall = 0
    while d < max_dist:
        moved = False
        for (mx, my) in ((hdx, hdy),):
            nx, ny = x + mx * step, y + my * step
            if blocked_by_npc(nx, ny):
                return d, (x, y), "NPC"
            t2 = None
            if inside(cur, nx, ny):
                t2 = cur
            else:
                frontier = [nb for nb in tris[cur][2] if nb != NO_NBR]
                second = set()
                for nb in frontier:
                    second.update(n2 for n2 in tris[nb][2] if n2 != NO_NBR)
                for cand in frontier + sorted(second - set(frontier) - {cur}):
                    if inside(cand, nx, ny):
                        t2 = cand
                        break
            if t2 is not None:
                cur = t2
                x, y, d = nx, ny, d + step
                moved = True
        if moved:
            continue
        # wall slide: project the held direction onto each wall edge of the
        # current triangle; take the slide that makes progress.
        slid = False
        vx, vy = tris[cur][0], tris[cur][1]
        for e in range(3):
            if tris[cur][2][e] != NO_NBR:
                continue
            a, b = e, (e + 1) % 3
            ex, ey = vx[b] - vx[a], vy[b] - vy[a]
            el = math.hypot(ex, ey)
            if el < 1e-6:
                continue
            ex, ey = ex / el, ey / el
            dot = hdx * ex + hdy * ey
            if abs(dot) < 0.2:
                continue
            sx_, sy_ = (ex, ey) if dot > 0 else (-ex, -ey)
            nx, ny = x + sx_ * step, y + sy_ * step
            if blocked_by_npc(nx, ny):
                return d, (x, y), "NPC"
            t2 = None
            if inside(cur, nx, ny):
                t2 = cur
            else:
                for cand in [nb for nb in tris[cur][2] if nb != NO_NBR]:
                    if inside(cand, nx, ny):
                        t2 = cand
                        break
            if t2 is not None:
                cur = t2
                x, y = nx, ny
                d += step          # time passes while sliding
                slid = True
                break
        if not slid:
            return d, (x, y), "WALL"
        stall += 1
        if stall > max_dist * 2:
            return d, (x, y), "STALL"
    return d, (x, y), "OK"

def astar_avoid(start, goal, avoid):
    """astar() with a temp set of avoided triangles (crossings INTO them
    refused) -- the same overlay shape as the IDLCK lock cut."""
    cents = [centroid(t) for t in range(ntris)]
    def h(t):
        return math.dist(cents[t], cents[goal])
    g = {start: 0.0}
    parent = {start: -1}
    pq = [(h(start), start)]
    closed = set()
    while pq:
        _, cur = heapq.heappop(pq)
        if cur in closed:
            continue
        if cur == goal:
            path = []
            while cur != -1:
                path.append(cur)
                cur = parent[cur]
            return path[::-1]
        closed.add(cur)
        for nb in tris[cur][2]:
            if nb == NO_NBR or nb in closed or nb in avoid:
                continue
            ng = g[cur] + math.dist(cents[cur], cents[nb])
            if ng < g.get(nb, float('inf')):
                g[nb] = ng
                parent[nb] = cur
                heapq.heappush(pq, (ng + h(nb), nb))
    return None

def tri_dist(t, px, py):
    if inside(t, px, py, eps=0.0):
        return 0.0
    vx, vy = tris[t][0], tris[t][1]
    return math.sqrt(min(PointSegDist2(vx[e], vy[e],
                                       vx[(e + 1) % 3], vy[(e + 1) % 3],
                                       px, py) for e in range(3)))

def legs_blocked(px, py, corners, excluded):
    """Names of solid NPCs whose HARD circle (r_sum) some route leg
    still crosses."""
    hit = set()
    ax, ay = px, py
    for (x, y) in corners:
        for name, nx, ny in SOLID_NPCS:
            if name in excluded:
                continue
            if seg_hits_circle(ax, ay, x, y, nx, ny, PLAYER_R + NPC_R):
                hit.add(name)
        ax, ay = x, y
    return hit

def build_route_from(px, py, mode):
    """mode: 'shipped' | 'detour' | 'full' (detour + sealed-passage
    reroute). Returns (corners, speech)."""
    st = None
    for t in range(ntris):
        if inside(t, px, py):
            st = t
            break
    if st is None:
        return None, "OFFMESH"
    p = astar(st, GOAL_TRI)
    if p is None:
        return None, "NOPATH"
    c = funnel(px, py, TARGET[0], TARGET[1], build_portals(p))
    if c is None:
        return None, "GUARD"
    excluded = {"Barret"}
    if mode != "shipped":
        c = insert_npc_detours(px, py, c, targets_excluded=excluded)
    if mode == "full":
        still = legs_blocked(px, py, c, excluded)
        if still:
            # sealed passage: temp-avoid every triangle a blocking body
            # overlaps (start/goal exempt) and reroute
            avoid = set()
            for name, nx, ny in SOLID_NPCS:
                if name not in still:
                    continue
                for t in range(ntris):
                    if t in (st, GOAL_TRI):
                        continue
                    if tri_dist(t, nx, ny) < PLAYER_R + NPC_R:
                        avoid.add(t)
            p2 = astar_avoid(st, GOAL_TRI, avoid)
            if p2 is not None:
                c2 = funnel(px, py, TARGET[0], TARGET[1], build_portals(p2))
                if c2 is not None:
                    c2 = insert_npc_detours(px, py, c2,
                                            targets_excluded=excluded)
                    if not legs_blocked(px, py, c2, excluded):
                        c = c2
    s, _, _ = route_to_speech(px, py, c)
    return c, s

def requery_follow(label, mode, max_queries=10):
    print(f"\n  -- iterative re-query follow: {label}")
    x, y = PLAYER
    for q in range(1, max_queries + 1):
        c, s = build_route_from(x, y, mode)
        if c is None:
            print(f"     query {q}: pipeline says {s}")
            return
        # first spoken leg = first FOLDED segment (what the player hears)
        cx, cy = x, y
        segs = []
        for (tx, ty) in c:
            dx, dy = tx - cx, ty - cy
            ln = math.hypot(dx, dy)
            cx, cy = tx, ty
            if ln < 1.0:
                continue
            sec = sector_index(math.degrees(math.atan2(dx, dy)) +
                               control_deg - 180.0)
            if segs and segs[-1][0] == sec:
                segs[-1][1] += ln
            else:
                segs.append([sec, ln])
        folded = []
        for sec, ln in segs:
            if folded and (ln < MIN_SEG or folded[-1][0] == sec):
                folded[-1][1] += ln
            else:
                folded.append([sec, ln])
        if not folded:
            print(f"     query {q}: route says very close")
            break
        sec, ln = folded[0]
        secs_spoken = max(1, int(ln / UNITS_PER_SEC + 0.5))
        walk_len = secs_spoken * UNITS_PER_SEC   # player walks the SPOKEN time
        qworld = sec * 45.0 - control_deg + 180.0
        d, (x, y), why = walk_sim3(x, y, qworld, walk_len)
        gap = math.hypot(x - TARGET[0], y - TARGET[1])
        print(f"     query {q}: '{s}' -> hold '{KDPAD[sec]}' {secs_spoken}s: "
              f"moved {d:.0f}u ({why}), now ({x:.0f},{y:.0f}), "
              f"{gap:.0f}u from Barret")
        if gap <= TALK_R:
            print(f"     REACHED Barret's talk radius after {q} quer"
                  f"{'y' if q == 1 else 'ies'}")
            return
    print("     did NOT reach talk radius")

print("\n=== EXPERIMENT 4: judge shipped vs NPC-detour under realistic "
      "follow " + "=" * 8)
c4, s4 = build_route_from(PLAYER[0], PLAYER[1], "full")
print(f"  full-pipeline corners: "
      f"{[(round(xx,1), round(yy,1)) for xx, yy in (c4 or [])]}")
print(f"  full-pipeline spoken : '{s4}'")
requery_follow("SHIPPED pipeline", "shipped")
requery_follow("DETOUR-ONLY pipeline", "detour")
requery_follow("FULL pipeline (detour + reroute)", "full")

# ================================================================================
# EXPERIMENT 5: is Barret reachable AT ALL under body-contact physics?
# Flood-fill the walkable mesh on an 8-unit grid, excluding points within
# CONTACT of any solid NPC, from the player's position; ask whether any
# reached point is within Barret's talk radius. Sweep CONTACT to find the
# threshold at which the room seals -- calibrates how pessimistic the
# 32+32 inference can be before it contradicts sighted play.
# ================================================================================
print("\n=== EXPERIMENT 5: reachability flood-fill vs contact distance " + "=" * 8)
GRID = 8.0
xs = [v for t in range(ntris) for v in tris[t][0]]
ys = [v for t in range(ntris) for v in tris[t][1]]
gx0, gx1 = min(xs) - GRID, max(xs) + GRID
gy0, gy1 = min(ys) - GRID, max(ys) + GRID
nx_ = int((gx1 - gx0) / GRID) + 1
ny_ = int((gy1 - gy0) / GRID) + 1

def flood_reach(contact):
    def cell_ok(ix, iy):
        x, y = gx0 + ix * GRID, gy0 + iy * GRID
        if any(math.hypot(x - nx, y - ny) < contact
               for _, nx, ny in SOLID_NPCS):
            return False
        return in_mesh(x, y)
    start = (int((PLAYER[0] - gx0) / GRID), int((PLAYER[1] - gy0) / GRID))
    seen = {start}
    stack = [start]
    best = 1e9
    while stack:
        ix, iy = stack.pop()
        x, y = gx0 + ix * GRID, gy0 + iy * GRID
        best = min(best, math.hypot(x - TARGET[0], y - TARGET[1]))
        for dx2 in (-1, 0, 1):
            for dy2 in (-1, 0, 1):
                nxt = (ix + dx2, iy + dy2)
                if nxt in seen or not (0 <= nxt[0] < nx_ and 0 <= nxt[1] < ny_):
                    continue
                if cell_ok(*nxt):
                    seen.add(nxt)
                    stack.append(nxt)
    return best, len(seen)

for contact in (64.0, 56.0, 48.0, 40.0):
    best, ncells = flood_reach(contact)
    verdict = "REACHABLE (talk radius)" if best <= TALK_R else "SEALED OFF"
    print(f"  contact {contact:4.0f}u: closest approach to Barret "
          f"{best:6.1f}u over {ncells} cells -> {verdict}")

print("\nDone.")
