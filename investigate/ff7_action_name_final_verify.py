#!/usr/bin/env python3
"""
ff7_action_name_final_verify.py -- FINAL pre-implementation verification of
battle action-name TTS resolution (v2.7), using signature-scanned kernel2
section bases (2026-07-11).

THE COMPLETE RESOLUTION ALGORITHM (all discovered/verified today):

  Trigger data: battle_actor_data (0xDC38E0):
      +0x0C command_index (0xDC38EC), +0x10 action_index (0xDC38F0)
  written at flash-message time by FFNx's display_battle_action_text
  replacement (or original sub_6D71FA without FFNx -- same addresses).

  Dispatch (from sub_6D1CC0 + exe tables, static):
      branch = byte[0x6D70A8 + command_index]
      branch 0/1: magic file, entry idx              (cmd 0x00, 0x02 Magic)
      branch 2:   idx<16 ? summon file : magic file  (cmd 0x03 Summon)
      branch 3/5: idx<128 ? item file entry idx      (cmd 0x04, 0x08 Item)
                  : idx<256 ? weapon file idx-128 : (none)
      branch 4:   static buffer 0xDC3640             (cmd 0x07)
      branch 6:   magic file, entry idx+72           (cmd 0x0D E.Skill)
      branch 7:   magic file, entry idx+128; idx==0x7F -> none  (cmd 0x14 Limit)
      branch 8:   0x9A9484 + idx*0x20                (cmd 0x20 enemy attack)
      branch 9:   generic default (no flash text; keep v2.5 labels)
      guard: biased entry index must stay < 0xE0 (game's own guard) and
             entry*2 < u16[base] (offset-table size).

  Section bases: kernel2 text lives in ONE heap block, sections in fixed
  order, each section = u16 offset table then 0xFF-terminated strings.
  Located at runtime by signature + walk-back (base such that
  u16[base] == distance to the signature string):
      magic  file: first entry 'Cure'         sig 'Cure|Cure2|'
      item   file: first entry 'Potion'       sig 'Potion|Hi-Potion|'
      weapon file: first entry 'Buster Sword' sig 'Buster Sword|'
      summon file: first entry 'Choco/Mog'    sig 'Choco/Mog|'
  Verified live today: magic base 0x22EF1560 entry 30 = 'Ice' (matches the
  spell cast in both test battles), item base 0x22EF1FB8 entry 0 = 'Potion'.

VERIFICATION PROTOCOL: one battle; use Attack, Magic, an Item, Limit if
available; enemies act on their own. Every action prints actor + resolved
name. Compare to the on-screen flash text / known actions.
"""
import sys, os, struct, ctypes, datetime, subprocess, time
from ctypes import wintypes

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"action_name_final_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

def open_ff7():
    out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe',
                                    '/FO', 'CSV', '/NH'], text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == 'ff7_en.exe':
            pid = int(parts[1])
            h = k32.OpenProcess(0x0410, False, pid)
            if not h:
                raise RuntimeError(f"OpenProcess failed (PID {pid})")
            print(f"FF7 running (PID {pid})")
            return h, pid
    raise RuntimeError("ff7_en.exe not found -- start FF7 first")

def read_mem(h, va, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok else None

def read_u8(h, va):
    b = read_mem(h, va, 1)
    return b[0] if b else None

def read_u16(h, va):
    b = read_mem(h, va, 2)
    return struct.unpack_from('<H', b)[0] if b and len(b) == 2 else None

def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b and len(b) == 4 else None

def ff7_decode(data, max_bytes=32):
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            break
        out.append(chr(b + 0x20) if b <= 0x5E else f'[{b:02X}]')
    return ''.join(out)

def encode(s):
    return bytes(ord(c) - 0x20 for c in s)

# -- addresses --------------------------------------------------------------------
G_ACTIVE_ACTOR_ID         = 0x00BE1170
G_BATTLE_MODEL_STATE      = 0x00BE1178
BATTLE_MODEL_STATE_STRIDE = 0x1AEC
BATTLE_COMMAND_ID_OFFSET  = 0x23
PARTY_LEADER              = 0x00DC08FF   # (only used for labels in the DLL)

BAD_COMMAND_INDEX = 0x00DC38EC
BAD_ACTION_INDEX  = 0x00DC38F0

DISPATCH_BYTE_TABLE = 0x006D70A8
ENEMY_ATK_TABLE     = 0x009A9484
CMD07_BUFFER        = 0x00DC3640

SIGS = {
    'magic':  encode('Cure') + b'\xff' + encode('Cure2') + b'\xff',
    'item':   encode('Potion') + b'\xff' + encode('Hi-Potion') + b'\xff',
    'weapon': encode('Buster Sword') + b'\xff',
    'summon': encode('Choco/Mog') + b'\xff',
}

def find_section_bases(h):
    """Signature scan over heap regions; walk-back rule for each base."""
    bases = {}
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while addr < 0x7FFF0000 and len(bases) < len(SIGS):
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State == 0x1000 and (mbi.Protect & 0xFF) in {0x04} and base > 0x01000000:
            blob = read_mem(h, base, min(size, 0x1000000))
            if blob:
                for name, sig in SIGS.items():
                    if name in bases:
                        continue
                    p = blob.find(sig)
                    if p < 0:
                        continue
                    str_va = base + p
                    for back in range(2, 0x800, 2):
                        cand = str_va - back
                        w = read_u16(h, cand)
                        if w == back:
                            bases[name] = cand
                            break
        addr = base + size
    return bases

def section_entry(h, base, idx):
    """Entry idx of a kernel2 text section: base + u16[base + idx*2].
    Guards: table size (first offset bounds the table) and 0xE0 game guard."""
    if base is None or idx >= 0xE0:
        return None
    tab_size = read_u16(h, base)
    if tab_size is None or idx * 2 >= tab_size:
        return None
    off = read_u16(h, base + idx * 2)
    if off is None:
        return None
    raw = read_mem(h, base + off, 32)
    return ff7_decode(raw) if raw else None

def resolve_action_name(h, bases, cmd, idx):
    if cmd > 0x20:
        return None, 'cmd out of range'
    branch = read_u8(h, DISPATCH_BYTE_TABLE + cmd)
    if branch is None:
        return None, 'branch unreadable'
    if branch in (0, 1):
        return section_entry(h, bases.get('magic'), idx), f'magic[{idx}]'
    if branch == 2:
        if idx < 16:
            return section_entry(h, bases.get('summon'), idx), f'summon[{idx}]'
        return section_entry(h, bases.get('magic'), idx), f'magic[{idx}] (summon>=16)'
    if branch in (3, 5):
        if idx < 128:
            return section_entry(h, bases.get('item'), idx), f'item[{idx}]'
        if idx < 256:
            return section_entry(h, bases.get('weapon'), idx - 128), f'weapon[{idx-128}]'
        return None, f'item idx {idx} out of battle range'
    if branch == 4:
        raw = read_mem(h, CMD07_BUFFER, 32)
        return (ff7_decode(raw) if raw else None), 'buffer 0xDC3640'
    if branch == 6:
        return section_entry(h, bases.get('magic'), idx + 72), f'magic[{idx}+72] (E.Skill)'
    if branch == 7:
        if idx == 0x7F:
            return None, 'limit ???? sentinel'
        return section_entry(h, bases.get('magic'), idx + 128), f'magic[{idx}+128] (Limit)'
    if branch == 8:
        raw = read_mem(h, ENEMY_ATK_TABLE + idx * 0x20, 0x20)
        return (ff7_decode(raw) if raw else None), f'enemy_atk[{idx}]'
    return None, 'generic default branch'

h, pid = open_ff7()
print("Scanning for kernel2 text section bases...")
bases = find_section_bases(h)
for name in SIGS:
    b = bases.get(name)
    first = section_entry(h, b, 0) if b else None
    print(f"  {name:7s}: " + (f"0x{b:08X}  entry0='{first}'" if b else "NOT FOUND"))
if not bases.get('magic') or not bases.get('item'):
    print("\nWARNING: core sections missing -- resolution will be degraded.")
print("\nPolling every 50ms. Ctrl+C to stop.\n")
print(f"{'time':>12}  {'actor':>5}  {'cmd':>5}  {'idx':>5}  name / path")

last_key = None
try:
    while True:
        actor_id = read_u8(h, G_ACTIVE_ACTOR_ID)
        if actor_id is None:
            exit_code = ctypes.c_ulong(0)
            k32.GetExitCodeProcess(h, ctypes.byref(exit_code))
            if exit_code.value != 259:
                print(f"-- FF7 process {pid} exited; waiting for restart --")
                k32.CloseHandle(h)
                while True:
                    time.sleep(2)
                    try:
                        h, pid = open_ff7()
                        bases = find_section_bases(h)
                        print("  (re-scanned section bases after restart)")
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
        # Announce edge: only resolve when the flash struct agrees with the
        # model-state command (the struct lags actor changes by ~1s; the
        # stale window would otherwise resolve the PREVIOUS action).
        synced = (cmd_idx & 0xFF) == cmd
        name, detail = resolve_action_name(h, bases, cmd_idx & 0xFF, act_idx & 0xFFFF)
        ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        shown = f"'{name}'" if name else '(generic)'
        print(f"{ts:>12}  {actor_id:5d}  0x{cmd:02X}  {act_idx:5d}  {shown}  [{detail}]"
              + ('' if synced else '  (struct not yet synced -- DLL would wait)'))
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
