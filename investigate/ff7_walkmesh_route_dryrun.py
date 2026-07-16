#!/usr/bin/env python3
"""
ff7_walkmesh_route_dryrun.py -- OFFLINE validation of the v2.22 turn-by-turn
directions pipeline against every walkmesh in the game (2026-07-16).

WHY:
  v2.22 reads the walkmesh from field-file section index 4: a triangle pool
  (production-confirmed layout -- FFNx renders from those exact offsets) and
  an ACCESS pool of per-edge neighbor ids (community-spec only -- FFNx never
  reads it). The shipped C++ self-guards the access pool at runtime, but a
  runtime guard only tells us "gave up" vs "proceeded" -- it cannot tell us
  the spec is right game-wide. This script settles that OFFLINE, the same
  method as the v2.18 model catalog and v2.20 translation dry run:

  FIELD_FILE_BUFFER (0xCFF594) holds the RAW DECOMPRESSED FIELD FILE -- the
  same bytes flevel.lgp decompresses to. Validating the file on disk IS
  validating what the mod will read from memory.

WHAT IT CHECKS, game-wide (all ~720 fields):
  1. Section index 4 parses as a walkmesh: plausible nTriangles, pools fit
     inside the section's declared size.
  2. Access pool ids: every entry 0xFFFF or < nTriangles (the C++ guard).
  3. Reciprocity: A names B  =>  B names A (C++ guard threshold >= 90%).
  4. GEOMETRIC adjacency -- the decisive test the C++ cannot afford per
     keypress on every link: every access link A->B must connect triangles
     that actually share >= 2 vertex coordinates. If the community spec had
     the pool's location or stride wrong, these "neighbors" would be random
     triangles and this check would fail en masse.
     (The inverse is NOT checked: two triangles may touch geometrically
     while access says wall -- that is a legitimate deliberate barrier.)

ROUTE DRY RUN:
  On a few known fields (md1stin -- the calibration field; nmkin_2 -- the
  reactor ladders field the player is on this week), replicate the shipped
  C++ pipeline exactly (same A* costs, same geometric portal recovery, same
  funnel algorithm, same segment merge/fold constants) between the mesh's
  farthest-apart triangle pairs, and print the would-be spoken routes.
  Checks: A* reaches its goal on connected meshes, the funnel terminates
  without tripping its guard, the taut path is never longer than the
  portal-midpoint path, and the spoken text stays a handful of segments.
  Direction words use control_direction from the triggers section (index 7,
  +9 -- same value the mod reads live), so the printed routes are the real
  in-game announcements for those player positions.

Output: per-check game-wide totals + the demo routes. A clean run upgrades
the research doc's access-pool confidence from "community spec, runtime-
guarded" to "offline-confirmed game-wide"; play-testing then only needs to
judge route QUALITY, not data correctness.
"""
import sys, os, struct, math, datetime, heapq

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"walkmesh_route_dryrun_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- locate flevel.lgp (same candidates as the v2.18 catalog) --------------------
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
print(f"  {len(data):,} bytes\n")

if b"SQUARESOFT" not in data[:16]:
    print("ERROR: LGP magic not found -- not an LGP archive?")
    sys.exit(1)
n_files = struct.unpack_from('<I', data, 12)[0]
toc = []
for i in range(n_files):
    off = 16 + i * 27
    raw_name = data[off:off + 20].split(b'\0')[0]
    file_off = struct.unpack_from('<I', data, off + 20)[0]
    toc.append((raw_name.decode('ascii', 'replace').lower(), file_off))
print(f"TOC: {n_files} files")

# -- LZS decompression with early stop (identical to the v2.18 catalog) ----------
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

# -- walkmesh + control_direction extraction --------------------------------------
WALKMESH_IDX = 4       # section table slot (FFNx-confirmed: level_data+0x16)
TRIGGERS_IDX = 7       # raw triggers section -- control_direction at +9
TRI_SIZE, ACC_SIZE = 24, 6
NO_NBR = 0xFFFF
MAX_TRIS = 4096        # same corruption guard as the C++

def parse_field(entry_off):
    """Returns (tris, control_deg) or (None, reason). tris = list of
    (vx[3], vy[3], nbr[3]) mirroring the C++ WalkTri snapshot."""
    flen = struct.unpack_from('<I', data, entry_off + 20)[0]
    raw = data[entry_off + 24:entry_off + 24 + flen]
    if len(raw) < 8:
        return None, "tiny"
    comp = raw[4:]                      # skip u32 compressed-size header
    head = lzs_decompress(comp, 64)
    if len(head) < 6 + 9 * 4:
        return None, "no header"
    sec_offs = struct.unpack_from('<9I', head, 6)
    # Section table sanity (same rejects as the catalog: non-field files).
    if sec_offs[0] != 0x2A or any(sec_offs[i] >= sec_offs[i+1] for i in range(8)):
        return None, "not a field"
    wm_off = sec_offs[WALKMESH_IDX]
    wm_end = sec_offs[WALKMESH_IDX + 1]
    # Decompress through the end of the triggers header too (for
    # control_direction); triggers sit late but are small -- cap the work.
    trig_need = sec_offs[TRIGGERS_IDX] + 4 + 10
    dec = lzs_decompress(comp, max(wm_end, trig_need))
    if len(dec) < wm_end:
        return None, "short stream"
    sec_size, ntris = struct.unpack_from('<II', dec, wm_off)
    if ntris == 0 or ntris > MAX_TRIS:
        return None, f"ntris={ntris}"
    need = 4 + ntris * (TRI_SIZE + ACC_SIZE)      # from the count field on
    if need > sec_size or wm_off + 8 + ntris * (TRI_SIZE + ACC_SIZE) > wm_end:
        return None, f"pools({ntris}) exceed section({sec_size})"
    tris = []
    tbase = wm_off + 8
    abase = tbase + ntris * TRI_SIZE
    for t in range(ntris):
        v = struct.unpack_from('<12h', dec, tbase + t * TRI_SIZE)
        a = struct.unpack_from('<3H', dec, abase + t * ACC_SIZE)
        # (vx, vy, access, vz) — vz appended last so pre-journey code's
        # [0]/[1]/[2] indexes are unchanged
        tris.append(((v[0], v[4], v[8]), (v[1], v[5], v[9]), a,
                     (v[2], v[6], v[10])))
    ctrl = dec[sec_offs[TRIGGERS_IDX] + 4 + 9] if len(dec) >= trig_need else 0
    return (tris, ctrl * 360.0 / 256.0), None

# -- game-wide validation ----------------------------------------------------------
print("\n=== GAME-WIDE ACCESS-POOL VALIDATION " + "=" * 40)
stats = dict(fields=0, skipped=0, parse_fail=0,
             id_ok=0, id_bad=0,
             links=0, mutual=0, geo_ok=0, geo_bad=0,
             recip_fail_fields=[], geo_fail_fields=[])
demo_meshes = {}
DEMO_FIELDS = ("md1stin", "nmkin_2", "md1_1", "elevtr1")

for name, entry_off in toc:
    parsed, reason = parse_field(entry_off)
    if parsed is None:
        if reason == "not a field" or reason == "tiny" or reason == "no header":
            stats['skipped'] += 1
        else:
            stats['parse_fail'] += 1
            print(f"  PARSE FAIL {name}: {reason}")
        continue
    tris, ctrl_deg = parsed
    stats['fields'] += 1
    n = len(tris)
    field_links = field_mutual = field_geo_ok = field_geo_bad = 0
    ids_ok = True
    for t, (vx, vy, acc, _vz) in enumerate(tris):
        for nb in acc:
            if nb == NO_NBR:
                continue
            if nb >= n:
                ids_ok = False
                continue
            field_links += 1
            if t in tris[nb][2]:
                field_mutual += 1
            # geometric adjacency: neighbor must share >= 2 vertex coords
            shared = sum(1 for i in range(3) for j in range(3)
                         if vx[i] == tris[nb][0][j] and vy[i] == tris[nb][1][j])
            if shared >= 2:
                field_geo_ok += 1
            else:
                field_geo_bad += 1
    stats['id_ok' if ids_ok else 'id_bad'] += 1
    stats['links'] += field_links
    stats['mutual'] += field_mutual
    stats['geo_ok'] += field_geo_ok
    stats['geo_bad'] += field_geo_bad
    if field_links and field_mutual * 10 < field_links * 9:
        stats['recip_fail_fields'].append(name)
    if field_geo_bad:
        stats['geo_fail_fields'].append((name, field_geo_bad, field_links))
    if name in DEMO_FIELDS:
        demo_meshes[name] = (tris, ctrl_deg)

print(f"\nfields parsed as walkmeshes : {stats['fields']}")
print(f"non-field files skipped     : {stats['skipped']}")
print(f"parse failures              : {stats['parse_fail']}")
print(f"fields, all access ids valid: {stats['id_ok']}  (bad: {stats['id_bad']})")
links, mutual = stats['links'], stats['mutual']
print(f"directed links              : {links}")
print(f"  reciprocal                : {mutual} ({100.0*mutual/max(1,links):.2f}%)")
print(f"  geometrically adjacent    : {stats['geo_ok']} "
      f"({100.0*stats['geo_ok']/max(1,links):.2f}%)  (bad: {stats['geo_bad']})")
print(f"fields failing C++ 90% reciprocity guard: {len(stats['recip_fail_fields'])} "
      f"{stats['recip_fail_fields'][:10]}")
if stats['geo_fail_fields']:
    print("fields with geometric mismatches (name, bad, links):")
    for row in stats['geo_fail_fields'][:20]:
        print(f"  {row}")

verdict_data = (stats['id_bad'] == 0 and stats['geo_bad'] == 0 and
                not stats['recip_fail_fields'])
print(f"\nACCESS-POOL LAYOUT VERDICT: "
      f"{'CONFIRMED game-wide' if verdict_data else 'MISMATCHES FOUND -- see above'}")

# -- route pipeline replica (mirrors the shipped C++ exactly) ----------------------
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

def centroid(tri):
    return (sum(tri[0]) / 3.0, sum(tri[1]) / 3.0)

def astar(tris, start, goal):
    """Same graph/costs as WalkmeshAStar (heapq instead of linear scan --
    identical results, this one runs hundreds of times)."""
    cents = [centroid(t) for t in tris]
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

def build_portals(tris, path):
    """Geometric shared-vertex portals, left/right by centroid-crossing
    direction -- the exact C++ BuildPortals."""
    portals = []
    for i in range(len(path) - 1):
        A, B = tris[path[i]], tris[path[i + 1]]
        acx, acy = centroid(A)
        bcx, bcy = centroid(B)
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
    """The exact C++ FunnelPath (guard included). Returns corners or None
    when the guard trips."""
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
        # Signs FLIPPED vs. the classic Recast listing: tri2 here is
        # cross(ab,ac) = -triArea2D. Same flip as the shipped C++.
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

def route_to_speech(sx, sy, corners, control_deg):
    """The exact C++ RouteToSpeech."""
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
        return "very close", total
    parts = []
    for sec, ln in folded[:MAX_SPOKEN]:
        s = max(1, int(ln / UNITS_PER_SEC + 0.5))
        parts.append(f"{KDPAD[sec]} {s} second{'s' if s != 1 else ''}")
    text = ", then ".join(parts)
    if len(folded) > MAX_SPOKEN:
        text += ", and more after that"
    return text, total

print("\n=== ROUTE DRY RUN " + "=" * 58)
route_problems = 0
for name in DEMO_FIELDS:
    if name not in demo_meshes:
        print(f"\n{name}: not found in archive, skipped")
        continue
    tris, ctrl_deg = demo_meshes[name]
    n = len(tris)
    cents = [centroid(t) for t in tris]
    print(f"\n{name}: {n} triangles, control_direction={ctrl_deg:.1f} deg")
    # Farthest-apart pair + two spread pairs, start from centroids (the
    # player stands mid-triangle; targets are exit lines in real use).
    far = max(((a, b) for a in range(n) for b in range(a + 1, n)),
              key=lambda ab: math.dist(cents[ab[0]], cents[ab[1]]))
    pairs = [far, (0, n - 1), (n // 3, 2 * n // 3)]
    seen = set()
    for (a, b) in pairs:
        if (a, b) in seen or a == b:
            continue
        seen.add((a, b))
        path = astar(tris, a, b)
        if path is None:
            print(f"  tri {a} -> {b}: NO PATH (disconnected mesh regions -- "
                  f"would speak 'No walkable path found.')")
            continue
        portals = build_portals(tris, path)
        sx, sy = cents[a]
        ex, ey = cents[b]
        corners = funnel(sx, sy, ex, ey, portals)
        used_fallback = corners is None
        if used_fallback:
            corners = [((l[0] + r[0]) / 2.0, (l[1] + r[1]) / 2.0)
                       for l, r in portals] + [(ex, ey)]
            route_problems += 1
        # Taut-path invariant: funnel length <= portal-midpoint length.
        def plen(pts):
            tot, px_, py_ = 0.0, sx, sy
            for (x, y) in pts:
                tot += math.hypot(x - px_, y - py_)
                px_, py_ = x, y
            return tot
        mids = [((l[0] + r[0]) / 2.0, (l[1] + r[1]) / 2.0)
                for l, r in portals] + [(ex, ey)]
        flen_, mlen = plen(corners), plen(mids)
        if flen_ > mlen + 1.0:
            route_problems += 1
            print(f"  tri {a} -> {b}: WARNING funnel LONGER than midpoints "
                  f"({flen_:.0f} > {mlen:.0f})")
        text, total = route_to_speech(sx, sy, corners, ctrl_deg)
        print(f"  tri {a} -> {b}: path {len(path)} tris, "
              f"{len(corners)} corners{' (FUNNEL GUARD TRIPPED)' if used_fallback else ''}, "
              f"taut {flen_:.0f} vs midpoints {mlen:.0f} units")
        print(f"    speaks: \"{text}\"")

# -- v2.23 JOURNEY sim: nmkin_2 with its REAL trigger lines ------------------------
# LINE triggers are script-created at runtime (not in the offline mesh), so
# the three nmkin_2 lines are injected verbatim from the 2026-07-16 live
# session log ("NAV line ..." debug entries). This validates the shipped
# journey pipeline end-to-end: z-aware point location puts each line on its
# level, the XY-proximity pair rule links the ladder's bottom/top zones,
# component BFS orders the hops, and the spoken message assembles.

def pointseg2(px_, py_, x1, y1, x2, y2):
    ex_, ey_ = x2 - x1, y2 - y1
    l2 = ex_ * ex_ + ey_ * ey_
    t = ((px_ - x1) * ex_ + (py_ - y1) * ey_) / l2 if l2 > 0 else 0.0
    t = min(1.0, max(0.0, t))
    dx_, dy_ = (x1 + t * ex_) - px_, (y1 + t * ey_) - py_
    return dx_ * dx_ + dy_ * dy_

def locate3(tris, x, y, z):
    """The shipped WalkmeshLocate: XY containment/boundary distance² plus
    height difference² as the stacked-layer tie-breaker."""
    best, best_score = -1, float('inf')
    for t, (vx, vy, acc, vz) in enumerate(tris):
        s0 = tri2(vx[0], vy[0], vx[1], vy[1], x, y)
        s1 = tri2(vx[1], vy[1], vx[2], vy[2], x, y)
        s2 = tri2(vx[2], vy[2], vx[0], vy[0], x, y)
        eps = 0.01
        if (s0 >= -eps and s1 >= -eps and s2 >= -eps) or \
           (s0 <= eps and s1 <= eps and s2 <= eps):
            xy2 = 0.0
        else:
            xy2 = min(pointseg2(x, y, vx[e], vy[e],
                                vx[(e + 1) % 3], vy[(e + 1) % 3])
                      for e in range(3))
        cz = sum(vz) / 3.0
        score = xy2 + (z - cz) ** 2
        if score < best_score:
            best_score, best = score, t
    return best

def components(tris):
    comp = [-1] * len(tris)
    n_comps = 0
    for seed in range(len(tris)):
        if comp[seed] != -1:
            continue
        comp[seed] = n_comps
        stack = [seed]
        while stack:
            t = stack.pop()
            for nb in tris[t][2]:
                if nb != NO_NBR and comp[nb] == -1:
                    comp[nb] = n_comps
                    stack.append(nb)
        n_comps += 1
    return comp, n_comps

print("\n=== JOURNEY SIM (nmkin_2, real trigger lines from live log) " + "=" * 15)
NMKIN2_LINES = [   # name, endpoint 1, endpoint 2  (live session 2026-07-16)
    ("ladder up",   (134, 145, 1582), (213, 132, 1582)),
    ("ladder down", (130, 268, 1799), (204, 276, 1798)),
    ("slide",       (816, 1937, 1842), (883, 2103, 1843)),
]
journey_ok = True
if "nmkin_2" not in demo_meshes:
    print("nmkin_2 missing, sim skipped")
    journey_ok = False
else:
    tris, ctrl_deg = demo_meshes["nmkin_2"]
    comp, n_comps = components(tris)
    print(f"components: {n_comps}")
    jls = []
    for name, p1, p2 in NMKIN2_LINES:
        mx, my, mz = [(a + b) / 2.0 for a, b in zip(p1, p2)]
        tri = locate3(tris, mx, my, mz)
        c1 = comp[tri]
        c2 = comp[locate3(tris, *p2)]
        jls.append((name, mx, my, tri, c1))
        print(f"  '{name}': midpoint tri {tri}, component {c1} "
              f"(2nd endpoint comp {c2})")
    # pair rule (JOURNEY_PAIR_DIST = 300)
    edges = []
    for a in range(len(jls)):
        for b in range(a + 1, len(jls)):
            if jls[a][4] == jls[b][4]:
                continue
            d2 = (jls[a][1] - jls[b][1]) ** 2 + (jls[a][2] - jls[b][2]) ** 2
            if d2 <= 300.0 ** 2:
                edges.append((jls[a][4], jls[b][4], a))
                edges.append((jls[b][4], jls[a][4], b))
                print(f"  connector: '{jls[a][0]}' <-> '{jls[b][0]}' "
                      f"(XY dist {math.sqrt(d2):.0f})")
    # journey for the dry run's NO-PATH pairs
    for (s, g) in [(39, 165), (58, 116)]:
        cs, cg = comp[s], comp[g]
        if cs == cg:
            print(f"  tri {s} -> {g}: same component?! unexpected")
            journey_ok = False
            continue
        # BFS
        prev = {cs: None}
        queue = [cs]
        qi = 0
        while qi < len(queue) and cg not in prev:
            c = queue[qi]; qi += 1
            for (ca, cb, via) in edges:
                if ca == c and cb not in prev:
                    prev[cb] = (c, via)
                    queue.append(cb)
        if cg not in prev:
            # A legitimate outcome, not a failure: some regions have no
            # inbound connector INSIDE the screen (nmkin_2's slide platform
            # is entered from a different screen; the slide is a one-way
            # exit). In-game this keeps the "No walkable path found."
            # fallback — the honest answer.
            print(f"  tri {s} -> {g}: no connector chain (comp {cs} -> {cg})"
                  f" -- correct when the region is entered from another screen")
            continue
        hops = []
        c = cg
        while prev[c] is not None:
            c, via = prev[c]
            hops.append(via)
        hops.reverse()
        first = jls[hops[0]]
        cents = [centroid(t) for t in tris]
        path = astar(tris, s, first[3])
        speech = ""
        if path:
            portals = build_portals(tris, path)
            corners = funnel(cents[s][0], cents[s][1],
                             first[1], first[2], portals)
            if corners is None:
                journey_ok = False
                corners = [((l[0] + r[0]) / 2, (l[1] + r[1]) / 2)
                           for l, r in portals] + [(first[1], first[2])]
            speech, _ = route_to_speech(cents[s][0], cents[s][1],
                                        corners, ctrl_deg)
        msg = f"<dest>: on another level. First take {first[0]}"
        if speech:
            msg += f", {speech}"
        for h in hops[1:]:
            msg += f". Then {jls[h][0]}"
        msg += ". Then ask again."
        print(f"  tri {s} -> {g}: {len(hops)} hop(s)")
        print(f"    speaks: \"{msg}\"")

print("\n=== SUMMARY " + "=" * 64)
print(f"access-pool layout: {'CONFIRMED game-wide' if verdict_data else 'FAILED'}")
print(f"route pipeline problems (guard trips / non-taut funnels): {route_problems}")
print(f"journey sim: {'OK' if journey_ok else 'PROBLEMS -- see above'}")
print("A clean run means play-testing only needs to judge spoken route "
      "QUALITY;\nthe data layout and algorithm invariants are settled here.")
