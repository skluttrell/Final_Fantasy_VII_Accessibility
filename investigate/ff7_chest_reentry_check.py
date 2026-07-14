#!/usr/bin/env python3
"""
ff7_chest_reentry_check.py -- Which chest-state bytes survive a field
reload? (2026-07-14, companion to ff7_chest_state_watch.py)

CONTEXT (from the watch run, chest_state_watch_20260714_110927.log,
field 120 = nmkin_1, model slot 8 = "fieldbg trb mety"):
  Opening the chest left exactly these persistent per-model changes
  (struct names from FFNx ff7.h field_event_data, anchor-confirmed):
    event+0x00 apply_kawai   u16: 1 -> 2       (glow effect state)
    event+0x68 currentFrame  u16: 0 -> 0x01D0  (lid animation held at end;
    event+0x6A lastFrame     u16: 0 -> 0x001D   0x01D0 = 29 << 4)
    anim +0x21 kawai_opcode  u8 : 0x0D -> 0xFF (glow off)
  plus a transient pulse at event+0x60 and the kawai params pointer at
  event+0x04 toggling continuously while the open chest is on screen.

QUESTION: which of these does the field INIT script restore when the
player re-enters the field (chest state is persisted in savemap event
flags and re-applied at load)? Whichever byte(s) come back with the OPEN
value are the mod's "Chest, opened" signal.

RUN: with the opened chest's field CURRENTLY LOADED. The script dumps the
open-state values, then waits for the player to leave the field and come
back (any exit), then dumps again and reports. Self-cued via SAPI.
"""
import sys, os, struct, ctypes, datetime, time

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"chest_reentry_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

try:
    import win32com.client
    _voice = win32com.client.Dispatch("SAPI.SpVoice")
    def say(text):
        print(f"[SAY] {text}")
        _voice.Speak(text, 1)
except Exception:
    def say(text):
        print(f"[SAY-noSAPI] {text}")

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

def r_i16(a):
    b = rpm(a, 2);  return struct.unpack('<h', b)[0] if b else None
def r_u32(a):
    b = rpm(a, 4);  return struct.unpack('<I', b)[0] if b else None

FIELD_ID             = 0xCC15D0
FIELD_FILE_BUFFER    = 0xCFF594
FIELD_EVENT_DATA_PTR = 0xCC0B60
EVENT_STRIDE         = 0x88
FIELD_ANIM_DATA_PTR  = 0xCFF738
ANIM_STRIDE          = 0x190

# Known values from the watch run (u16 reads except kawai u8):
CLOSED = dict(apply_kawai=1, anim_id=None, currentFrame=0x0000, lastFrame=0x0000, kawai=0x0D)
OPEN   = dict(apply_kawai=2, anim_id=None, currentFrame=0x01D0, lastFrame=0x001D, kawai=0xFF)

def model_labels():
    buf = r_u32(FIELD_FILE_BUFFER)
    if not buf or buf < 0x401000:
        return None
    head = rpm(buf, 64)
    if not head:
        return None
    sec_off = struct.unpack_from('<I', head, 6 + 2 * 4)[0]
    if not (6 < sec_off < 0x200000):
        return None
    sh = rpm(buf + sec_off, 8)
    if not sh:
        return None
    sec_size = struct.unpack_from('<I', sh, 0)[0]
    if not (8 <= sec_size <= 0x10000):
        return None
    sec = rpm(buf + sec_off + 4, sec_size)
    if not sec:
        return None
    n = struct.unpack_from('<H', sec, 2)[0]
    if n > 64:
        return None
    p = 6
    out = []
    for _ in range(n):
        if p + 2 > len(sec): return None
        ln = struct.unpack_from('<H', sec, p)[0]; p += 2
        if ln == 0 or ln > 64 or p + ln > len(sec): return None
        nm = sec[p:p + ln].decode('ascii', 'replace').lower(); p += ln
        if nm.endswith('.char'):
            nm = nm[:-5]
        out.append(nm.replace('_', ' '))
        p += 2 + 8 + 4
        if p + 2 > len(sec): return None
        na = struct.unpack_from('<H', sec, p)[0]; p += 2
        if na > 64: return None
        p += 30
        for _ in range(na):
            if p + 2 > len(sec): return None
            al = struct.unpack_from('<H', sec, p)[0]; p += 2
            if al > 64 or p + al + 2 > len(sec): return None
            p += al + 2
    return out

def chest_slot():
    labels = model_labels()
    if not labels:
        return None
    for i, l in enumerate(labels):
        if 'fieldbg' in l and ('trb' in l or 'trbox' in l):
            return i
    return None

def dump(slot, tag):
    earr = r_u32(FIELD_EVENT_DATA_PTR)
    aarr = r_u32(FIELD_ANIM_DATA_PTR)
    if not earr or not aarr:
        return None
    ev = rpm(earr + slot * EVENT_STRIDE, EVENT_STRIDE)
    an = rpm(aarr + slot * ANIM_STRIDE, 0x30)
    if not ev or not an:
        return None
    vals = dict(
        apply_kawai=struct.unpack_from('<H', ev, 0x00)[0],
        anim_id=ev[0x64],
        currentFrame=struct.unpack_from('<H', ev, 0x68)[0],
        lastFrame=struct.unpack_from('<H', ev, 0x6A)[0],
        kawai=an[0x21],
    )
    print(f"{tag}: slot={slot} " +
          " ".join(f"{k}=0x{v:04X}" if k != 'kawai' and k != 'anim_id'
                   else f"{k}=0x{v:02X}" for k, v in vals.items()))
    return vals

say("Chest re-entry check running.")
fid0 = r_i16(FIELD_ID)
slot = chest_slot()
if slot is None:
    say("No chest model on this field. Stand on the field with the chest and rerun.")
    sys.exit(1)

# GUARD (lesson from the first run, chest_reentry_20260714_115918.log): the
# game had been RESTARTED between the watch run and the check, so the
# "open" pre-reload dump actually held CLOSED values and the whole verdict
# was meaningless. The open state must be observed IN THIS SESSION: if the
# chest currently reads closed (currentFrame == 0 and glow on), have the
# player open it and wait until the open values appear before prompting
# the leave-and-return step.
before = dump(slot, f"pre-reload (field {fid0})")
if before and before['currentFrame'] == 0 and before['kawai'] != 0xFF:
    say("The chest currently reads CLOSED. Walk to it and open it now; "
        "I will wait. If it will not open, say so in chat and stop me.")
    t0 = time.time()
    while time.time() - t0 < 600:
        time.sleep(0.2)
        if r_i16(FIELD_ID) != fid0:
            continue                      # wandered off; keep waiting
        cur = dump(slot, "waiting")
        if cur and (cur['currentFrame'] != 0 or cur['kawai'] == 0xFF):
            before = cur
            break
    else:
        say("Timed out waiting for the chest to open. Rerun when ready.")
        sys.exit(1)
    say("Open detected.")

print(f"OPEN reference: {before}")
say(f"Recorded the open chest on field {fid0}. "
    "Now leave this field through any exit, then come straight back. "
    "Do not restart the game.")

seen_away = False
t0 = time.time()
while time.time() - t0 < 600:
    time.sleep(0.25)
    fid = r_i16(FIELD_ID)
    if fid is None:
        print("Process gone."); break
    if fid != fid0:
        if not seen_away:
            say("Field left. Now come back.")
        seen_away = True
        continue
    if seen_away:
        time.sleep(1.5)          # let the init scripts finish
        slot2 = chest_slot()
        if slot2 is None:
            continue
        after = dump(slot2, f"AFTER RELOAD (field {fid0})")
        if not after:
            continue
        print("\nVERDICT per byte (closed / open / after-reload):")
        confirmed = []
        for k in before:
            c = CLOSED.get(k)
            o = before[k]
            a = after[k]
            # A byte is a usable signal only if open DIFFERS from closed
            # AND the reload restored the open value (first-run lesson:
            # before==after==closed must never count as a match).
            match_open = (c is not None and o != c and a == o)
            note = ("RESTORED-OPEN -> usable state signal" if match_open else
                    "reverted to closed value" if c is not None and a == c
                    else "no closed/open contrast" if c is None or o == c
                    else "differs from both")
            cs = f"0x{c:04X}" if c is not None else "  ?  "
            print(f"  {k:<13} {cs} / 0x{o:04X} / 0x{a:04X}   {note}")
            if match_open:
                confirmed.append(k)
        say(f"Done. {len(confirmed)} byte{'s' if len(confirmed) != 1 else ''} "
            f"restored to the open value: {', '.join(confirmed) if confirmed else 'none'}. "
            "You can keep playing.")
        break
else:
    print("Timed out waiting for re-entry.")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
