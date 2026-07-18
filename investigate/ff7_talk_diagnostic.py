#!/usr/bin/env python3
"""
ff7_talk_diagnostic.py -- Live "why can't I talk to them?" probe
(2026-07-16; user stuck talking to Jessie at the nmkin_2 ladder tutorial
while the pathfinder says they are next to her).

WHAT IT CHECKS (the three ways a talk attempt fails silently):
  1. TALK RADIUS: dialog only triggers within the entity's per-model talk
     radius (field_event_data +0x74, s16, walkmesh units) — the pathfinder
     said "very close" at 26 units, but if her radius is smaller, or the
     game measures from a different point, OK does nothing.
  2. HEIGHT: the pathfinder's distance is 2D. If she is up/down a ladder
     (z differs by hundreds of units), she can be 26 XY-units away and
     unreachable.
  3. WRONG TARGET: some scenes trigger from a LINE zone (the ladder
     itself), not from the person — so the lines' distances are reported
     too.

Every 2 seconds for 2 minutes: speaks the nearest non-player model's
distance / height difference / talk radius verdict, and logs EVERY model
(slot, label, pos, dz, triangle, talk radius, entity) plus all enabled
LINE zones with distances. Walk around while it runs; the spoken value
updates live, so it doubles as a hot/cold beacon.

Speech via PowerShell System.Speech (per feedback_investigation_scripts —
never pywin32).
"""
import sys, os, struct, ctypes, datetime, time, math, subprocess

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"talk_diagnostic_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def say(text):
    print(f"[SAY] {text}")
    try:
        safe = text.replace("'", "''")
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command",
             f"Add-Type -AssemblyName System.Speech; "
             f"(New-Object System.Speech.Synthesis.SpeechSynthesizer)."
             f"Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"  (speech failed: {e})")

# -- attach ----------------------------------------------------------------------
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

def find_pid(name='ff7_en.exe'):
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

def r_u16(a):
    b = rpm(a, 2);  return struct.unpack('<H', b)[0] if b else None
def r_i16(a):
    b = rpm(a, 2);  return struct.unpack('<h', b)[0] if b else None
def r_u32(a):
    b = rpm(a, 4);  return struct.unpack('<I', b)[0] if b else None

# -- addresses (all long-confirmed) ------------------------------------------------
FIELD_EVENT_DATA_PTR  = 0xCC0B60
FIELD_PLAYER_MODEL_ID = 0xCC162C
FIELD_N_MODELS        = 0xCFF73E
FIELD_ID              = 0xCC15D0
FIELD_FILE_BUFFER     = 0xCFF594
FIELD_LINE_COUNT      = 0xCC088C
FIELD_LINE_ARRAY      = 0xCC1F70
STRIDE  = 0x88
OFF_POS = 0x0C
OFF_ENT = 0x5D
OFF_TKON= 0x61   # talk-enabled byte: the TLKON opcode's arg written raw
                 # (handler disasm 2026-07-16, scratch tlkon_static run:
                 # mov [event_data + slot*0x88 + 0x61], arg). Expected
                 # polarity per script docs: 0 = talkable, 1 = disabled —
                 # CONFIRMED live if Jessie (untalkable) reads 1.
OFF_TALK= 0x74
OFF_TRI = 0x78

# -- model labels: live v2.16 model-loader parse (raw field file section 2) -------
def model_labels():
    labels = {}
    buf = r_u32(FIELD_FILE_BUFFER)
    if not buf:
        return labels
    head = rpm(buf, 6 + 9 * 4)
    if not head:
        return labels
    offs = struct.unpack_from('<9I', head, 6)
    sec = rpm(buf + offs[2], 0x4000)          # model loader section
    if not sec or len(sec) < 12:
        return labels
    pos = 4                                    # skip u32 size prefix
    blank, nmod, scale = struct.unpack_from('<HHH', sec, pos)
    pos += 6
    for m in range(min(nmod, 32)):
        if pos + 2 > len(sec):
            break
        ln = struct.unpack_from('<H', sec, pos)[0]
        pos += 2
        if ln > 128 or pos + ln > len(sec):
            break
        name = sec[pos:pos + ln].decode('ascii', 'replace')
        pos += ln
        labels[m] = name.replace('.char', '')
        pos += 2 + 8 + 4                       # u16 unknown, HRC, scale
        if pos + 2 > len(sec):
            break
        nanim = struct.unpack_from('<H', sec, pos)[0]
        pos += 2 + 30                          # nAnims, light block
        for a in range(min(nanim, 64)):
            if pos + 2 > len(sec):
                break
            al = struct.unpack_from('<H', sec, pos)[0]
            pos += 2 + al + 2
    return labels

say("Talk diagnostic running for two minutes. Stand near the person, "
    "then try walking slowly while I read distances.")

labels = model_labels()
fid = r_i16(FIELD_ID)
print(f"FIELD_ID = {fid}")
print(f"model labels: {labels}\n")

deadline = time.time() + 120
last_spoken = 0.0
while time.time() < deadline:
    arr  = r_u32(FIELD_EVENT_DATA_PTR)
    pmid = r_u16(FIELD_PLAYER_MODEL_ID)
    nmod = r_u16(FIELD_N_MODELS)
    if not arr or pmid is None or nmod is None or pmid >= min(nmod, 32):
        time.sleep(0.5)
        continue
    pdata = rpm(arr + pmid * STRIDE, STRIDE)
    if not pdata:
        time.sleep(0.5)
        continue
    px, py, pz = [v >> 12 for v in struct.unpack_from('<3i', pdata, OFF_POS)]
    ptri = struct.unpack_from('<h', pdata, OFF_TRI)[0]
    now = datetime.datetime.now().strftime('%H:%M:%S')
    print(f"[{now}] player pos=({px},{py},{pz}) tri={ptri}")

    rows = []
    for m in range(min(nmod, 32)):
        if m == pmid:
            continue
        d = rpm(arr + m * STRIDE, STRIDE)
        if not d:
            continue
        mx, my, mz = [v >> 12 for v in struct.unpack_from('<3i', d, OFF_POS)]
        tri  = struct.unpack_from('<h', d, OFF_TRI)[0]
        talk = struct.unpack_from('<h', d, OFF_TALK)[0]
        tkon = d[OFF_TKON]
        ent  = d[OFF_ENT]
        dist = math.hypot(mx - px, my - py)
        dz   = mz - pz
        lbl  = labels.get(m, f"model {m}")
        rows.append((dist, m, lbl, mx, my, mz, dz, tri, talk, ent, tkon))
        print(f"  m={m:2d} '{lbl}' pos=({mx},{my},{mz}) dist={dist:.0f} "
              f"dz={dz} tri={tri} talk_radius={talk} tlkon={tkon} ent={ent}")

    n_lines = r_u16(FIELD_LINE_COUNT) or 0
    for i in range(min(n_lines, 32)):
        le = rpm(FIELD_LINE_ARRAY + i * 0x18, 0x18)
        if not le:
            continue
        v = struct.unpack_from('<6h', le)
        enabled = le[0x0C]
        mx, my = (v[0] + v[3]) / 2.0, (v[1] + v[4]) / 2.0
        dist = math.hypot(mx - px, my - py)
        print(f"  line {i} enabled={enabled} mid=({mx:.0f},{my:.0f},"
              f"{(v[2]+v[5])//2}) dist={dist:.0f} ent={le[0x0D]}")

    # Speak the nearest model's verdict, at most every 4s.
    if rows and time.time() - last_spoken >= 4.0:
        rows.sort()
        dist, m, lbl, mx, my, mz, dz, tri, talk, ent, tkon = rows[0]
        verdict = ("within talk radius" if talk > 0 and dist <= talk
                   else f"outside talk radius {talk}")
        extra = f", height differs by {abs(dz)}" if abs(dz) > 50 else ""
        tk = ", talk disabled" if tkon else ", talk enabled"
        say(f"Nearest: {lbl}, {dist:.0f} units, {verdict}{tk}{extra}.")
        last_spoken = time.time()

    time.sleep(2.0)

say("Diagnostic finished.")
print("\ndone")
