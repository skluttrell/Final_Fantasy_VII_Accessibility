#!/usr/bin/env python3
"""
ff7_kernel2_action_name_verify.py -- Live verification of the enemy action
name table discovered via static disassembly (2026-07-05).

Chain: sub_6D71FA (request queue) -> consumer at 0x6D72E9 -> sub_6D1CC0
(dispatch by opcode 0x16/0x17/0x19) -> jump table @ 0x6D7080 (remapped via
byte table @ 0x6D70A8) -> sub_41963C(internal_id, idx, 8) -> for
internal_id==9: fixed table at 0x009A9484, stride 0x20, direct index by idx.

Confirmed manually: idx 0-3 decoded to "Machine Gun"/"Tonfa"/"Bite"/"Tentacle"
during a live battle. This script polls G_ACTIVE_ACTOR_ID / commandID /
actionIdx (already used by BattleActionThread in proxy.cpp) and prints the
looked-up name from the 0x9A9484 table each time the actor changes, so it
can be compared against the actual on-screen action text.

Run while in battle; press Ctrl+C to stop.
"""
import sys, os, struct, ctypes, datetime, subprocess, time

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_action_name_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def read_u16(h, va):
    b = read_mem(h, va, 2)
    return struct.unpack_from('<H', b)[0] if b else None

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
G_SMALL_BATTLE_MODEL_STATE = 0x00BF23B8
BATTLE_SMALL_MODEL_STRIDE = 0x74
BATTLE_ACTION_IDX_OFFSET = 0x3E

ACTION_NAME_TABLE = 0x009A9484
ACTION_NAME_STRIDE = 0x20

h = open_ff7()
print("Polling every 100ms. Ctrl+C to stop.\n")
print(f"{'time':>8}  {'actor':>5}  {'cmd':>5}  {'idx':>4}  name")

last_key = None
try:
    while True:
        actor_id = read_u8(h, G_ACTIVE_ACTOR_ID)
        if actor_id is None:
            time.sleep(0.1)
            continue
        cmd = read_u8(h, G_BATTLE_MODEL_STATE + actor_id * BATTLE_MODEL_STATE_STRIDE + BATTLE_COMMAND_ID_OFFSET)
        idx = read_u16(h, G_SMALL_BATTLE_MODEL_STATE + actor_id * BATTLE_SMALL_MODEL_STRIDE + BATTLE_ACTION_IDX_OFFSET)
        if cmd is None or idx is None or cmd == 0:
            time.sleep(0.1)
            continue
        key = (actor_id, cmd, idx)
        if key == last_key:
            time.sleep(0.05)
            continue
        last_key = key
        name_data = read_mem(h, ACTION_NAME_TABLE + idx * ACTION_NAME_STRIDE, ACTION_NAME_STRIDE) if idx < 64 else None
        name = ff7_decode(name_data) if name_data else '(idx out of range)'
        ts = time.strftime('%H:%M:%S')
        print(f"{ts:>8}  {actor_id:5d}  0x{cmd:02X}  {idx:4d}  '{name}'")
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
