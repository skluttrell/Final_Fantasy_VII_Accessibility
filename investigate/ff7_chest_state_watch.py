#!/usr/bin/env python3
"""
ff7_chest_state_watch.py -- Live discovery of the chest OPEN/CLOSED state
byte (2026-07-14, v2.18 follow-up; plan from TODO.txt "Items category").

GOAL:
  Opened chests stay on the walkmesh with an open lid, so the Items
  category keeps listing them. Find the per-model byte that persistently
  distinguishes open from closed -- including across a field re-entry
  (scripts restore chest state from savemap event flags at field load) --
  so the pathfinder can announce "Chest, opened".

METHOD (no guessing which byte -- diff everything the model owns):
  For the chest's model slot we sample BOTH per-model structs the engine
  keeps:
    - field_event_data entry:      FIELD_EVENT_DATA_PTR (0xCC0B60) ->
                                   slot*0x88, 0x88 bytes
    - field_animation_data entry:  FIELD_ANIM_DATA_PTR (0xCFF738) ->
                                   slot*0x190, 0x190 bytes
  (0xCFF738 and the 0x190 stride are DOUBLY confirmed: FFNx ff7.h names
  the global with the address in a comment, and our own LADER-handler
  disassembly (line_triggers_static log) reads the same global with the
  same stride.)

  Phase 1  find chest model slot(s) by label ("fieldbg"+"trb"): parse the
           model-loader section from FIELD_FILE_BUFFER, v2.16 format.
  Phase 2  BASELINE: ~5s of samples while the player stands still; bytes
           that never change = the stable mask (animation playback bytes
           churn constantly and are excluded by this).
  Phase 3  the player walks to the chest and OPENS it; any stable byte
           that changes is logged (offset, old -> new) and beeped.
  Phase 4  ~10s after the last change, bytes still holding their new
           value = persistent open-state candidates (spoken + logged).
  Phase 5  the player LEAVES the field and RETURNS; the script re-finds
           the chest slot and reports each candidate's value after the
           reload -- candidates that came back with the "open" value are
           the real state bytes.

  Self-cued via SAPI + beeps throughout (standing rule: the blind player
  never needs to read the console mid-test). Ctrl+C for early summary.
"""
import sys, os, struct, ctypes, datetime, time

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"chest_state_watch_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

import winsound
try:
    import win32com.client
    _voice = win32com.client.Dispatch("SAPI.SpVoice")
    def say(text):
        print(f"[SAY] {text}")
        _voice.Speak(text, 1)
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

# -- addresses --------------------------------------------------------------------
FIELD_ID              = 0xCC15D0
GAME_MODE             = 0xCC0D89
FIELD_FILE_BUFFER     = 0xCFF594
FIELD_N_MODELS        = 0xCFF73E
FIELD_EVENT_DATA_PTR  = 0xCC0B60
EVENT_STRIDE          = 0x88
FIELD_ANIM_DATA_PTR   = 0xCFF738
ANIM_STRIDE           = 0x190
SECTION_TABLE_OFF     = 6
MODEL_SECTION_IDX     = 2

def model_labels():
    """Parse the model-loader section (v2.16 format) from process memory.
    Returns list of stripped lowercase labels, or None."""
    buf = r_u32(FIELD_FILE_BUFFER)
    if not buf or buf < 0x401000:
        return None
    head = rpm(buf, 64)
    if not head:
        return None
    sec_off = struct.unpack_from('<I', head, SECTION_TABLE_OFF + MODEL_SECTION_IDX * 4)[0]
    if not (SECTION_TABLE_OFF < sec_off < 0x200000):
        return None
    sec_head = rpm(buf + sec_off, 8)
    if not sec_head:
        return None
    sec_size = struct.unpack_from('<I', sec_head, 0)[0]
    if not (8 <= sec_size <= 0x10000):
        return None
    sec = rpm(buf + sec_off + 4, sec_size)
    if not sec:
        return None
    n_models = struct.unpack_from('<H', sec, 2)[0]
    if n_models > 64:
        return None
    p = 6
    labels = []
    for _ in range(n_models):
        if p + 2 > len(sec): return None
        nlen = struct.unpack_from('<H', sec, p)[0]; p += 2
        if nlen == 0 or nlen > 64 or p + nlen > len(sec): return None
        name = sec[p:p + nlen].decode('ascii', 'replace').lower()
        p += nlen
        if name.endswith('.char'):
            name = name[:-5]
        labels.append(name.replace('_', ' '))
        p += 2 + 8 + 4
        if p + 2 > len(sec): return None
        nanim = struct.unpack_from('<H', sec, p)[0]; p += 2
        if nanim > 64: return None
        p += 30
        for _ in range(nanim):
            if p + 2 > len(sec): return None
            alen = struct.unpack_from('<H', sec, p)[0]; p += 2
            if alen > 64 or p + alen + 2 > len(sec): return None
            p += alen + 2
    return labels

def find_chest_slots():
    labels = model_labels()
    if labels is None:
        return None, None
    slots = [i for i, l in enumerate(labels)
             if 'fieldbg' in l and ('trb' in l or 'trbox' in l)]
    return slots, labels

def sample(slot):
    """One combined sample: event entry + anim entry, or None."""
    earr = r_u32(FIELD_EVENT_DATA_PTR)
    aarr = r_u32(FIELD_ANIM_DATA_PTR)
    if not earr or earr < 0x401000 or not aarr or aarr < 0x401000:
        return None
    ev = rpm(earr + slot * EVENT_STRIDE, EVENT_STRIDE)
    an = rpm(aarr + slot * ANIM_STRIDE, ANIM_STRIDE)
    if ev is None or an is None:
        return None
    return ev + an   # offsets 0..0x87 = event, 0x88.. = anim (+0x88 bias)

def off_name(off):
    if off < EVENT_STRIDE:
        return f"event+0x{off:02X}"
    return f"anim+0x{off - EVENT_STRIDE:02X}"

# -- main -------------------------------------------------------------------------
say("Chest state watch running.")
fid0 = r_i16(FIELD_ID)
slots, labels = find_chest_slots()
if not slots:
    say("No chest models found on this field. Are you on the right field?")
    print(f"field={fid0}: labels={labels}")
    sys.exit(1)

slot = slots[0]
say(f"Found {len(slots)} chest model{'s' if len(slots) != 1 else ''} on field "
    f"{fid0}. Watching model slot {slot}.")
print(f"field={fid0} chest slots={slots} labels={labels}\n")

# Phase 2: baseline -----------------------------------------------------------
say("Stand still for 6 seconds while I take a baseline. Do not move.")
base_samples = []
t0 = time.time()
while time.time() - t0 < 6.0:
    s = sample(slot)
    if s:
        base_samples.append(s)
    time.sleep(0.1)
if len(base_samples) < 10:
    say("Could not sample the chest. Aborting.")
    sys.exit(1)
size = len(base_samples[0])
stable = bytearray(1 for _ in range(size))
for s in base_samples[1:]:
    for i in range(size):
        if s[i] != base_samples[0][i]:
            stable[i] = 0
baseline = base_samples[-1]
n_stable = sum(stable)
print(f"Baseline: {len(base_samples)} samples, {n_stable}/{size} stable bytes\n")

# Phase 3: watch for the open ----------------------------------------------------
say("Baseline done. Now walk to the chest and open it. I beep on changes.")
changes = {}          # off -> (baseline_val, latest_val, n_changes, first_ts)
prev = baseline
last_change_t = None
last_beep = 0.0
open_snapshot = None
t0 = time.time()
aborted_field = False
while True:
    time.sleep(0.1)
    fid = r_i16(FIELD_ID)
    mode = r_u8(GAME_MODE)
    if fid is None:
        print("Process gone."); sys.exit(1)
    if fid != fid0:
        aborted_field = True
        break                     # player left early -> treat as phase 5
    if mode != 0:
        continue                  # dialog/menu pauses are fine, keep waiting
    s = sample(slot)
    if not s:
        continue
    now = time.time()
    for i in range(size):
        if stable[i] and s[i] != prev[i]:
            if i not in changes:
                changes[i] = [baseline[i], s[i], 1, now - t0]
            else:
                changes[i][1] = s[i]
                changes[i][2] += 1
            print(f"[{now - t0:6.1f}s] {off_name(i)}: "
                  f"0x{prev[i]:02X} -> 0x{s[i]:02X}")
            last_change_t = now
            if now - last_beep > 0.5:
                winsound.Beep(1000, 50); last_beep = now
    prev = s
    # 10s of quiet after the first change = settled
    if last_change_t and now - last_change_t > 10.0:
        open_snapshot = s
        break
    if now - t0 > 300:
        say("Five minutes with no settle. Stopping the watch phase.")
        open_snapshot = s
        break

# Phase 4: persistent candidates --------------------------------------------------
persistent = {}
if open_snapshot:
    for off, (bval, lval, n, ts) in sorted(changes.items()):
        cur = open_snapshot[off]
        keep = cur != baseline[off]
        if keep:
            persistent[off] = (baseline[off], cur)
        print(f"  {off_name(off)}: base=0x{bval:02X} now=0x{cur:02X} "
              f"changes={n} first@{ts:.1f}s  "
              f"{'PERSISTENT-CANDIDATE' if keep else 'transient'}")
    say(f"{len(persistent)} persistent candidate byte"
        f"{'s' if len(persistent) != 1 else ''}. "
        "Now leave this field and come back through the exit.")
else:
    say("No settled snapshot; leaving field-reentry check anyway.")

# Phase 5: field re-entry check ----------------------------------------------------
t0 = time.time()
seen_away = aborted_field
while time.time() - t0 < 300:
    time.sleep(0.25)
    fid = r_i16(FIELD_ID)
    if fid is None:
        break
    if fid != fid0:
        seen_away = True
        continue
    if seen_away and fid == fid0:
        time.sleep(1.5)           # let init scripts finish
        slots2, _ = find_chest_slots()
        if not slots2:
            continue
        s = sample(slots2[0])
        if not s:
            continue
        print(f"\nRE-ENTRY (field {fid0}, slot {slots2[0]}):")
        confirmed = []
        for off, (bval, oval) in sorted(persistent.items()):
            cur = s[off]
            status = ("CONFIRMED open-state byte" if cur == oval else
                      f"reverted to 0x{cur:02X}")
            print(f"  {off_name(off)}: closed=0x{bval:02X} open=0x{oval:02X} "
                  f"after-reload=0x{cur:02X}  {status}")
            if cur == oval:
                confirmed.append(off)
        say(f"Re-entry check done. {len(confirmed)} confirmed state byte"
            f"{'s' if len(confirmed) != 1 else ''}. You can stop playing.")
        break
else:
    print("Re-entry not observed within 5 minutes.")

print(f"\nLog saved to: {_log_path}")
say("Chest watch finished. Log saved.")
_log_file.close()
