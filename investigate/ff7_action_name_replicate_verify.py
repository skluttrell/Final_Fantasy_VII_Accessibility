#!/usr/bin/env python3
"""
ff7_action_name_replicate_verify.py -- Live end-to-end verification of the
battle action NAME resolution pipeline for v2.7 (2026-07-11).

This replicates, with pure memory READS (no game-code calls), exactly what
FF7's own flash-message dispatcher does:

  sub_6D1CC0 (dispatcher):
      branch = byte[0x6D70A8 + commandID]; jmp [0x6D7080 + branch*4]
      branch -> get_kernel_text(SECTION, action_idx, 8):
        branch 0/1 -> section 0 (magic names)      branch 2 -> section 6 (summon)
        branch 3/5 -> section 4 (item namespace)   branch 6 -> section 2 (E.Skill)
        branch 7 -> section 3 (limit breaks)       branch 8 -> section 9 (enemy attacks)
        branch 4 -> special sub_6D70F1 buffer 0xDC3640 (cmd 0x07 only)
        branch 9 -> generic default (idx forced 0) -- keep v2.5 labels

  get_kernel_text == sub_41963C (0x41963C), fully disassembled 2026-07-11:
      section 4: idx remapped through threshold tables:
          for i in 0..4: if idx < u16[0x7B748A+i*2]:
              idx -= u16[0x7B7488+i*2]; section = u8[0x7B7498+i]; break
      section 3 && idx == 0x7F -> idx = 0xFF ('????' sentinel)
      idx == 0xFF -> no name
      section < 4: bias = u8[0x7B74A0+section]; if idx+bias < 0xE0: idx += bias
      file = u8[0x7B74A8+section]
      file != 0xFF -> kernel2_get_text(file+8, idx)
      section 6 -> kernel2_get_text(0x11, idx) if idx < 0x10
                   else kernel2_get_text(9, idx)
      section 9 -> text at 0x9A9484 + idx*0x20 (stride table, live-verified
                   2026-07-05: Machine Gun/Tonfa/Bite/Tentacle)

  kernel2_get_text == sub_419457 (0x419457):
      base = 0x9A13C8 + u16[0x9A7FC8 + file*2]
      text = base + u16[base + idx*2]

Data source polled (live-verified today, kernel2_result_verify log):
  battle_actor_data struct at 0xDC38E0 (FFNx ff7.h struct, base confirmed by
  formation_entry==0xDC38E8):
      +0x08 formation_entry (pending flag), +0x0C command_index,
      +0x10 action_index
  These are written at flash time by FFNx's display_battle_action_text
  replacement (FFNx battle.cpp line 57) or by original sub_6D71FA -- same
  addresses either way.

VERIFICATION PROTOCOL: fight one battle using Attack, Magic, Item, and Limit
if available; let enemies act. Compare each printed name to the on-screen
flash text. SUCCESS = names match for every command type.

Run while in battle; press Ctrl+C to stop.
"""
import sys, os, struct, ctypes, datetime, subprocess, time

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"action_name_replicate_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
            return h, pid
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

def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b else None

def ff7_decode(data, max_bytes=32):
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            break
        if b <= 0x5E:
            out.append(chr(b + 0x20))
        else:
            out.append(f'[{b:02X}]')
    return ''.join(out)

# -- game addresses (all confirmed today or earlier) -----------------------------
G_ACTIVE_ACTOR_ID         = 0x00BE1170
G_BATTLE_MODEL_STATE      = 0x00BE1178
BATTLE_MODEL_STATE_STRIDE = 0x1AEC
BATTLE_COMMAND_ID_OFFSET  = 0x23

BAD_COMMAND_INDEX = 0x00DC38EC   # battle_actor_data +0x0C
BAD_ACTION_INDEX  = 0x00DC38F0   # battle_actor_data +0x10

DISPATCH_BYTE_TABLE = 0x006D70A8
# section-4 (item namespace) remap tables inside get_kernel_text:
# thresholds 0x7B748A, subtract 0x7B7488, section remap 0x7B7498,
# idx bias 0x7B74A0, section->file table 0x7B74A8
T_THRESH = 0x007B748A
T_SUB    = 0x007B7488
T_SECT   = 0x007B7498
T_BIAS   = 0x007B74A0
T_FILE   = 0x007B74A8

K2_OFFSET_TABLE = 0x009A7FC8   # u16 per file id
K2_TEXT_BASE    = 0x009A13C8
ENEMY_ATK_TABLE = 0x009A9484   # + idx*0x20, section 9
CMD07_BUFFER    = 0x00DC3640   # special branch output buffer

# branch index -> kernel section (from jump table 0x6D7080, extracted
# statically today; branch 4 = special buffer, branch 9 = generic default)
BRANCH_TO_SECTION = {0: 0, 1: 0, 2: 6, 3: 4, 5: 4, 6: 2, 7: 3, 8: 9}

def kernel2_get_text(h, file_id, idx):
    off = read_u16(h, K2_OFFSET_TABLE + file_id * 2)
    if off is None:
        return None
    base = K2_TEXT_BASE + off
    entry_off = read_u16(h, base + idx * 2)
    if entry_off is None:
        return None
    raw = read_mem(h, base + entry_off, 32)
    return ff7_decode(raw) if raw else None

def resolve_action_name(h, cmd, idx):
    """Full replication of dispatcher + get_kernel_text. Returns
    (name, detail) where detail explains the path taken."""
    if cmd > 0x20:
        return None, 'cmd out of dispatch range'
    branch = read_u8(h, DISPATCH_BYTE_TABLE + cmd)
    if branch is None:
        return None, 'branch table unreadable'
    if branch == 9:
        return None, 'generic default branch'
    if branch == 4:
        raw = read_mem(h, CMD07_BUFFER, 32)
        return (ff7_decode(raw) if raw else None), 'special buffer 0xDC3640'
    section = BRANCH_TO_SECTION.get(branch)
    if section is None:
        return None, f'unknown branch {branch}'
    detail = f'branch {branch} -> section {section}'

    # -- get_kernel_text replication --
    if section == 4:
        for i in range(5):
            thresh = read_u16(h, T_THRESH + i * 2)
            if thresh is not None and idx < thresh:
                sub = read_u16(h, T_SUB + i * 2)
                new_sect = read_u8(h, T_SECT + i)
                idx -= sub
                section = new_sect
                detail += f' -> item remap[{i}] sect {section} idx {idx}'
                break
    if section == 3 and idx == 0x7F:
        return None, detail + ' -> ???? sentinel'
    if idx == 0xFF:
        return None, detail + ' -> idx 0xFF (no name)'
    if section < 4:
        bias = read_u8(h, T_BIAS + section)
        if bias is not None and idx + bias < 0xE0:
            idx += bias
    if section == 6:
        file_id = 0x11 if idx < 0x10 else 9
        return kernel2_get_text(h, file_id, idx), detail + f' (summon file {file_id})'
    if section == 9:
        raw = read_mem(h, ENEMY_ATK_TABLE + idx * 0x20, 0x20)
        return (ff7_decode(raw) if raw else None), detail + ' (enemy attack table)'
    file_id = read_u8(h, T_FILE + section)
    if file_id is None or file_id == 0xFF:
        return None, detail + f' (file table gave 0xFF)'
    return kernel2_get_text(h, file_id + 8, idx), detail + f' (file {file_id}+8)'

h, pid = open_ff7()
print("Polling every 50ms. Ctrl+C to stop.\n")
print(f"{'time':>12}  {'actor':>5}  {'cmd':>5}  {'idx':>5}  name / path")

last_key = None
try:
    while True:
        # Re-attach transparently if the game restarts (lesson from this
        # morning: the first verify script silently read a dead PID for two
        # whole battles).
        actor_id = read_u8(h, G_ACTIVE_ACTOR_ID)
        if actor_id is None:
            exit_code = ctypes.c_ulong(0)
            k32.GetExitCodeProcess(h, ctypes.byref(exit_code))
            if exit_code.value != 259:   # STILL_ACTIVE
                print(f"-- FF7 process {pid} exited; waiting for restart --")
                k32.CloseHandle(h)
                while True:
                    time.sleep(2)
                    try:
                        h, pid = open_ff7()
                        break
                    except RuntimeError:
                        pass
            time.sleep(0.1)
            continue
        cmd = read_u8(h, G_BATTLE_MODEL_STATE
                      + actor_id * BATTLE_MODEL_STATE_STRIDE
                      + BATTLE_COMMAND_ID_OFFSET)
        cmd_idx = read_u32(h, BAD_COMMAND_INDEX)
        act_idx = read_u32(h, BAD_ACTION_INDEX)
        if cmd is None or cmd == 0 or cmd_idx is None or act_idx is None:
            time.sleep(0.1)
            continue
        key = (actor_id, cmd, cmd_idx, act_idx)
        if key == last_key:
            time.sleep(0.05)
            continue
        last_key = key
        # Resolve from the battle_actor_data fields (flash-time values), but
        # show both cmd sources for cross-checking.
        name, detail = resolve_action_name(h, cmd_idx & 0xFF, act_idx & 0xFFFF)
        ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        shown = f"'{name}'" if name else '(none)'
        print(f"{ts:>12}  {actor_id:5d}  0x{cmd:02X}  {act_idx:5d}  {shown}  [{detail}]"
              + ('' if (cmd_idx & 0xFF) == cmd else f'  NOTE: struct cmd={cmd_idx}'))
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
