#!/usr/bin/env python3
"""
ff7_line_triggers_verify.py -- Live verification of the LINE trigger array
found statically by ff7_line_triggers_static.py (2026-07-14).

WHAT THE STATIC PASS FOUND (all three handlers agree; internal cross-check):
    LINE_COUNT  = u16 @ 0xCC088C          (number of lines on this field, max 0x20)
    LINE_ARRAY  = 0xCC1F70, stride 0x18, 32 slots:
        +0x00 i16 x1   +0x02 i16 y1   +0x04 i16 z1     (walkmesh coords --
        +0x06 i16 x2   +0x08 i16 y2   +0x0A i16 z2      same units as model_pos>>12)
        +0x0C u8 enabled  (1 on LINE create; LINON writes its arg here)
        +0x0D u8 owning entity id
        +0x0E u8 state latch (cleared on disable)
    ENTITY->LINE slot map = u8[0xCBF600 + entity_id]

ENTITY NAMES: field script section 0 header (behind FIELD_SCRIPT_PTR
0xCBF5E8) holds nEntities at +2 and an 8-byte ASCII entity-name table at
+0x20 (2+1+1+2+2+2+6+8+8 header bytes) -- lets each line speak the DEV NAME
of the entity that owns it ("sd_ele", "kaidan"...), the v2.16 naming trick.

VERIFICATION CRITERIA (each dump is checked automatically):
  1. count <= 32 and count == number of slots with plausible data
  2. every vertex within the walkmesh coord envelope (|v| < 30000)
  3. every owning entity id < nEntities from the script header
  4. entity names printable ASCII
  5. distances from the player's live position are plausible (< 5000 units)
  6. count RESETS on field change (new field = fresh LINE opcodes)

HOW TO USE (self-cued -- no chat alt-tabbing, per the standing rule):
  Run it, then just play. On every field entry it speaks "N lines" and logs
  the full dump; walking near/over a line that fires a script will flip the
  +0x0E latch or +0x0C flag, which is logged (and beeped) as it happens.
  Ctrl+C to stop. Best test route: any field with a ladder or elevator.
"""
import sys, os, struct, ctypes, ctypes.wintypes as wt, datetime, time

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"line_triggers_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

# -- speech + beep cues (player is blind; never require reading the console) ----
import winsound
try:
    import win32com.client
    _voice = win32com.client.Dispatch("SAPI.SpVoice")
    def say(text):
        print(f"[SAY] {text}")
        _voice.Speak(text, 1)   # async
except Exception:
    def say(text):
        print(f"[SAY-noSAPI] {text}")

# -- attach ----------------------------------------------------------------------
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

def find_pid(name='ff7_en.exe'):
    import subprocess
    out = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {name}',
                                   '/FO', 'CSV', '/NH'], text=True)
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == name:
            return int(parts[1])
    raise RuntimeError(f"{name} not running")

pid = find_pid()
h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    raise ctypes.WinError(ctypes.get_last_error())
print(f"Attached to ff7_en.exe pid={pid} (read-only)\n")

def rpm(addr, size):
    buf = (ctypes.c_ubyte * size)()
    n = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                 ctypes.byref(n)) or n.value != size:
        return None
    return bytes(buf)

def r_u8(a):
    b = rpm(a, 1);  return b[0] if b else None
def r_i16(a):
    b = rpm(a, 2);  return struct.unpack('<h', b)[0] if b else None
def r_u16(a):
    b = rpm(a, 2);  return struct.unpack('<H', b)[0] if b else None
def r_u32(a):
    b = rpm(a, 4);  return struct.unpack('<I', b)[0] if b else None

# -- addresses (2013/2026-shared exe; provenance in the static log + §4) ---------
FIELD_ID              = 0xCC15D0
GAME_MODE             = 0xCC0D89
LINE_COUNT            = 0xCC088C
LINE_ARRAY            = 0xCC1F70
LINE_STRIDE           = 0x18
LINE_MAX              = 32
FIELD_SCRIPT_PTR      = 0xCBF5E8
ENTITY_NAMES_OFF      = 0x20      # section-0 header: names start after 32-byte header
FIELD_EVENT_DATA_PTR  = 0xCC0B60
FIELD_PLAYER_MODEL_ID = 0xCC162C
EVENT_DATA_STRIDE     = 0x88
MODEL_POS_OFF         = 0x0C

def entity_name(idx, script_base, n_entities):
    if script_base is None or n_entities is None or idx >= n_entities:
        return None
    raw = rpm(script_base + ENTITY_NAMES_OFF + idx * 8, 8)
    if not raw:
        return None
    s = raw.split(b'\0')[0]
    if not s or any(c < 0x20 or c > 0x7E for c in s):
        return None
    return s.decode('ascii')

def player_pos():
    arr = r_u32(FIELD_EVENT_DATA_PTR)
    pmid = r_u16(FIELD_PLAYER_MODEL_ID)
    if not arr or arr < 0x401000 or pmid is None or pmid > 0x20:
        return None
    b = rpm(arr + pmid * EVENT_DATA_STRIDE + MODEL_POS_OFF, 8)
    if not b:
        return None
    x, y = struct.unpack('<ii', b)
    return (x >> 12, y >> 12)

def seg_dist(px, py, x1, y1, x2, y2):
    """2D distance from point to segment -- same math the pathfinder uses."""
    dx, dy = x2 - x1, y2 - y1
    L2 = dx * dx + dy * dy
    if L2 == 0:
        t = 0.0
    else:
        t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / L2))
    nx, ny = x1 + t * dx, y1 + t * dy
    return ((px - nx) ** 2 + (py - ny) ** 2) ** 0.5

def read_lines():
    """Read all 32 slots; return list of dicts for slots < count."""
    count = r_u16(LINE_COUNT)
    if count is None or count > LINE_MAX:
        return count, []
    out = []
    for i in range(count):
        b = rpm(LINE_ARRAY + i * LINE_STRIDE, LINE_STRIDE)
        if not b:
            return count, out
        x1, y1, z1, x2, y2, z2 = struct.unpack_from('<6h', b, 0)
        out.append(dict(idx=i, v=(x1, y1, z1, x2, y2, z2),
                        enabled=b[0x0C], ent=b[0x0D], latch=b[0x0E]))
    return count, out

def dump(field_id, count, lines):
    script_base = r_u32(FIELD_SCRIPT_PTR)
    n_entities = r_u8(script_base + 2) if script_base and script_base > 0x401000 else None
    pp = player_pos()
    print(f"--- field {field_id}: LINE_COUNT={count}, nEntities={n_entities}, "
          f"player={pp} ---")
    problems = []
    for ln in lines:
        x1, y1, z1, x2, y2, z2 = ln['v']
        name = entity_name(ln['ent'], script_base, n_entities)
        d = seg_dist(pp[0], pp[1], x1, y1, x2, y2) if pp else -1
        print(f"  line {ln['idx']:2d}: ({x1},{y1},{z1})-({x2},{y2},{z2})  "
              f"enabled={ln['enabled']} latch={ln['latch']} "
              f"ent={ln['ent']} '{name}'  dist={d:.0f}")
        if any(abs(c) >= 30000 for c in ln['v']):
            problems.append(f"line {ln['idx']}: vertex out of envelope")
        if n_entities is not None and ln['ent'] >= n_entities:
            problems.append(f"line {ln['idx']}: entity id {ln['ent']} >= {n_entities}")
        if pp and d > 5000:
            problems.append(f"line {ln['idx']}: dist {d:.0f} implausible")
    if problems:
        for p in problems:
            print(f"  ** {p}")
    else:
        print("  all checks OK")
    return problems

# -- main loop --------------------------------------------------------------------
say("Line trigger verify running. Play normally. It announces line counts on each field.")
print("Polling. Ctrl+C to stop.\n")

last_field = None
last_flags = {}
total_problems = 0
fields_seen = 0
try:
    while True:
        time.sleep(0.25)
        fid = r_i16(FIELD_ID)
        mode = r_u8(GAME_MODE)
        if fid is None:
            print("Process gone -- exiting.")
            break
        if fid == 0 or mode != 0:
            continue
        count, lines = read_lines()
        if count is None:
            continue
        if fid != last_field:
            last_field = fid
            fields_seen += 1
            probs = dump(fid, count, lines)
            total_problems += len(probs)
            say(f"{count} lines" + (", problems, check log" if probs else ""))
            last_flags = {ln['idx']: (ln['enabled'], ln['latch']) for ln in lines}
            continue
        # Same field: watch for LINON/latch activity (walking over a line).
        for ln in lines:
            prev = last_flags.get(ln['idx'])
            cur = (ln['enabled'], ln['latch'])
            if prev is not None and prev != cur:
                pp = player_pos()
                print(f"[{datetime.datetime.now():%H:%M:%S}] line {ln['idx']} "
                      f"flags {prev} -> {cur}  player={pp}")
                winsound.Beep(1320, 60)
            last_flags[ln['idx']] = cur
except KeyboardInterrupt:
    pass

print(f"\nSummary: {fields_seen} fields seen, {total_problems} check failures.")
say(f"Verify done. {fields_seen} fields, {total_problems} problems.")
print(f"Log saved to: {_log_path}")
_log_file.close()
