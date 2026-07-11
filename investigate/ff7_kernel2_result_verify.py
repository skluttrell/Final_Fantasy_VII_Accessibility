#!/usr/bin/env python3
"""
ff7_kernel2_result_verify.py -- Live verification of the kernel2 lookup
RESULT pointer at 0xDC208C as the source of exact battle-action flash text
(2026-07-11).

WHY THIS EXPERIMENT (the last step before final v2.7 implementation):
  v2.5's BattleActionThread speaks generic command-ID labels ("Cloud, Magic")
  because we have no safe way to resolve the exact ability name:
    - Calling GET_KERNEL_TEXT at 0x016E4E3C crashes: that address is FFNx's
      trampoline heap, not original game code (confirmed 2026-07-05).
    - The small-model actionIdx (+0x3E) is an animation counter, not an
      ability id (disproved 2026-07-06, ff7_kernel2_action_name_verify.py).
    - The request struct 0xDC38E8 (section/idx) tracks the action, but we
      have no verified way to turn section+idx into a name: the 0x9A9484
      stride-0x20 table only decodes correctly for a handful of low enemy-
      attack indices and returns garbage/blanks for magic (sect=2), items
      (sect=4), and limits (sect=20) (kernel2_request_verify_20260706).

  Static disassembly found that the game's OWN flash-message path calls the
  real kernel2 lookup sub_41963C(section, idx, 8) (real CALL at 0x6D72C6
  inside the request consumer) and stores the returned text pointer at
  0xDC208C (FFVII-Accessibility-Research.md section 14, menu module block).
  If that pointer, dereferenced at flash time, holds the exact FF7-encoded
  name string the flash message displays ("Bolt", "Tentacle", "Potion",
  "Braver"...), the mod can read it with two ReadProcessMemory-equivalent
  reads and ZERO foreign-thread calls into game code -- the same rawptr
  pattern already used for dialog text.

WHAT THIS SCRIPT DOES:
  Polls at 20ms (fast, to catch the lookup close to the pending=1 edge):
    - G_ACTIVE_ACTOR_ID / commandID   (the v2.5 announce trigger)
    - KERNEL2_REQUEST pending/section/idx (0xDC38E8/EC/F0)
    - RESULT_PTR at 0xDC208C -> dereference -> hex dump + FF7-decode
  Prints a row whenever ANY of (actor, cmd, section, idx, ptr, first bytes)
  changes, so the timeline shows exactly when the result pointer updates
  relative to the action starting.

HOW TO JUDGE THE RESULT (while playing one battle, use each command type):
  - Attack, Magic (cast a named spell e.g. Bolt), Item (use a Potion),
    Limit Break if available; let enemies act too.
  - SUCCESS: the decoded string at RESULT_PTR matches the on-screen flash
    text for each action, updating at/near the same poll as the cmd change.
  - FAILURE modes to watch for: pointer stale from a previous menu lookup;
    pointer valid only for some sections; pointer into a scratch buffer
    that is overwritten before our poll sees it.

Run while in battle; press Ctrl+C to stop.
"""
import sys, os, struct, ctypes, datetime, subprocess, time

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_result_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

k32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

def open_ff7():
    out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe',
                                    '/FO', 'CSV', '/NH'], text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == 'ff7_en.exe':
            pid = int(parts[1])
            h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
            if not h:
                raise RuntimeError(f"OpenProcess failed (PID {pid})")
            print(f"FF7 running (PID {pid})")
            return h
    raise RuntimeError("ff7_en.exe not found -- start FF7 first")

def read_mem(h, va, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size, ctypes.byref(read))
    if not ok or read.value < size:
        return None
    return buf.raw

def read_u8(h, va):
    b = read_mem(h, va, 1)
    return b[0] if b else None

def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b else None

def ff7_decode(data, max_bytes=32):
    """Minimal FF7 text decode: 0x00-0x5E map to ASCII (+0x20), 0xFF ends.
    Unknown bytes shown as [hex] so encoding surprises are visible in the log."""
    extra = {0xE0: '\\n'}
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            break
        if b <= 0x5E:
            out.append(chr(b + 0x20))
        elif b in extra:
            out.append(extra[b])
        else:
            out.append(f'[{b:02X}]')
    return ''.join(out)

G_ACTIVE_ACTOR_ID         = 0x00BE1170
G_BATTLE_MODEL_STATE      = 0x00BE1178
BATTLE_MODEL_STATE_STRIDE = 0x1AEC
BATTLE_COMMAND_ID_OFFSET  = 0x23

KERNEL2_REQUEST_PENDING = 0x00DC38E8
KERNEL2_REQUEST_SECTION = 0x00DC38EC
KERNEL2_REQUEST_IDX     = 0x00DC38F0

KERNEL2_RESULT_PTR = 0x00DC208C   # written by sub_41963C -- THE thing under test

# Plausible pointer range for kernel2 text: anywhere in the exe's data/heap
# space. 32-bit process, so anything from the image base up to ~2GB. We only
# use this to avoid dereferencing obvious garbage (0, small ints, 0xFFFFFFFF).
def ptr_plausible(p):
    return p is not None and 0x00400000 <= p < 0x7FFF0000

h = open_ff7()
print("Polling every 20ms. Ctrl+C to stop.\n")
print(f"{'time':>12}  {'actor':>5}  {'cmd':>5}  {'pend':>4}  {'sect':>4}  {'idx':>4}  "
      f"{'result_ptr':>10}  decoded / hex")

last_key = None
try:
    while True:
        actor_id = read_u8(h, G_ACTIVE_ACTOR_ID)
        if actor_id is None:
            time.sleep(0.1)
            continue
        cmd = read_u8(h, G_BATTLE_MODEL_STATE
                      + actor_id * BATTLE_MODEL_STATE_STRIDE
                      + BATTLE_COMMAND_ID_OFFSET)
        pending = read_u32(h, KERNEL2_REQUEST_PENDING)
        section = read_u32(h, KERNEL2_REQUEST_SECTION)
        idx     = read_u32(h, KERNEL2_REQUEST_IDX)
        rptr    = read_u32(h, KERNEL2_RESULT_PTR)
        if cmd is None or cmd == 0:
            # Not in battle / idle: keep polling but stay silent.
            time.sleep(0.1)
            continue

        text_bytes = read_mem(h, rptr, 32) if ptr_plausible(rptr) else None
        # Include the first 8 raw bytes in the change key so we also catch the
        # game rewriting the buffer IN PLACE without changing the pointer.
        head = text_bytes[:8] if text_bytes else None
        key = (actor_id, cmd, section, idx, rptr, head)
        if key == last_key:
            time.sleep(0.02)
            continue
        last_key = key

        if text_bytes:
            decoded = ff7_decode(text_bytes)
            hexdump = text_bytes[:16].hex(' ')
            desc = f"'{decoded}'  |  {hexdump}"
        else:
            desc = '(ptr not readable)'
        ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"{ts:>12}  {actor_id:5d}  0x{cmd:02X}  {pending:4d}  {section:4d}  "
              f"{idx:4d}  0x{rptr:08X}  {desc}")
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
