#!/usr/bin/env python3
"""
ff7_kernel2_request_verify.py -- Live verification of the kernel2 REQUEST
struct as the true action-name index source (2026-07-06).

Background:
  ff7_kernel2_action_name_verify.py polled the small-battle-model-state
  actionIdx field (G_SMALL_BATTLE_MODEL_STATE + actor*0x74 + 0x3E) and found
  it climbs 1->30 identically regardless of whether the actor is an enemy
  attacking, Cloud attacking, or Cloud using a Limit Break. That field is NOT
  the ability identifier -- it is some unrelated counter (likely animation
  frame). The idx 1-3 "Tonfa/Bite/Tentacle" matches were coincidental.

  Static disassembly (ff7_kernel2_xref_scan.py, sub_6D71FA @ 0x6D71FA) shows
  the REAL request queue the game itself populates before it does its own
  kernel2 lookup for on-screen text:
    KERNEL2_REQUEST_BASE = 0x00DC38E8
      +0x00 DWORD request_pending  (set to 1 by sub_6D71FA, cleared by the
                                     consumer at 0x6D72E9 after processing)
      +0x04 DWORD section          (0xDC38EC)
      +0x08 DWORD idx              (0xDC38F0)
  The consumer only clears request_pending -- section/idx are left holding
  their last value, so polling them (not just catching the pending=1 edge)
  should be reliable.

  This script polls section/idx directly (ignoring the small-model actionIdx
  entirely) alongside actor_id/commandID, and decodes via the same
  0x9A9484 stride-0x20 static table used before, purely to see whether THIS
  idx correlates with distinct on-screen actions instead of climbing
  monotonically.

Run while in battle; press Ctrl+C to stop.
"""
import sys, os, struct, ctypes, datetime, subprocess, time

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_request_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    extra = {0xE0: '\n', 0xFF: '[END]'}
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

G_ACTIVE_ACTOR_ID = 0x00BE1170
G_BATTLE_MODEL_STATE = 0x00BE1178
BATTLE_MODEL_STATE_STRIDE = 0x1AEC
BATTLE_COMMAND_ID_OFFSET = 0x23

KERNEL2_REQUEST_PENDING = 0x00DC38E8
KERNEL2_REQUEST_SECTION = 0x00DC38EC
KERNEL2_REQUEST_IDX     = 0x00DC38F0

ACTION_NAME_TABLE = 0x009A9484
ACTION_NAME_STRIDE = 0x20

h = open_ff7()
print("Polling every 100ms. Ctrl+C to stop.\n")
print(f"{'time':>8}  {'actor':>5}  {'cmd':>5}  {'pend':>4}  {'sect':>4}  {'idx':>4}  name")

last_key = None
try:
    while True:
        actor_id = read_u8(h, G_ACTIVE_ACTOR_ID)
        if actor_id is None:
            time.sleep(0.1)
            continue
        cmd = read_u8(h, G_BATTLE_MODEL_STATE + actor_id * BATTLE_MODEL_STATE_STRIDE + BATTLE_COMMAND_ID_OFFSET)
        pending = read_u32(h, KERNEL2_REQUEST_PENDING)
        section = read_u32(h, KERNEL2_REQUEST_SECTION)
        idx     = read_u32(h, KERNEL2_REQUEST_IDX)
        if cmd is None or pending is None or section is None or idx is None or cmd == 0:
            time.sleep(0.1)
            continue
        key = (actor_id, cmd, section, idx)
        if key == last_key:
            time.sleep(0.05)
            continue
        last_key = key
        name_data = read_mem(h, ACTION_NAME_TABLE + idx * ACTION_NAME_STRIDE, ACTION_NAME_STRIDE) if idx < 64 else None
        name = ff7_decode(name_data) if name_data else '(idx out of range)'
        ts = time.strftime('%H:%M:%S')
        print(f"{ts:>8}  {actor_id:5d}  0x{cmd:02X}  {pending:4d}  {section:4d}  {idx:4d}  '{name}'")
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
