#!/usr/bin/env python3
"""
ff7_battle_action_scan.py — Discover battle action text addresses; monitor live.

PHASE 1 — Code scan (just needs FF7 running, no battle required):
  Reads ~300 bytes at display_battle_action_text_42782A (0x42782A) and
  display_battle_action_text_sub_6D71FA (0x6D71FA).  For each function,
  decodes every instruction that embeds an absolute data address or a
  relative call target.  This lets us identify all data pointers the function
  uses without a full disassembler.

  Key offsets documented in FFNx ff7_data.h:
    FUNC + 0x52  ← abs32 embedded in a MOV instruction = g_active_actor_id address
    FUNC + 0x77  ← CALL rel32 target = display_battle_action_text_sub_6D71FA

  From FFNx ff7.h struct definitions:
    battle_model_state        — size 0x1AEC bytes; commandID at +0x23 (byte)
    battle_model_state_small  — size 0x074  bytes; actionIdx at +0x3E (uint16)

  Tentative base addresses (from absolute addresses in ff7.h struct comments):
    g_battle_model_state       actor 0 base = 0x00BE1178
    g_small_battle_model_state actor 0 base = unknown (Phase 1 finds it)

PHASE 2 — Live monitor (enter a battle first):
  Polls *g_active_actor_id every 100 ms.  When it changes to a valid slot
  (0–2 = party, 4–9 = enemy), reads commandID from g_battle_model_state and
  actionIdx from g_small_battle_model_state (if found in Phase 1), then
  speaks a brief summary.

  Note: get_kernel_text (which maps commandID+actionIdx to a human-readable
  name) cannot be called from outside the process.  Phase 1 prints all CALL
  targets found in sub_6D71FA — one of those is get_kernel_text.  That address
  will be hardcoded in ff7_addresses.h and called in-process by the DLL.

HOW TO RUN:
  1. Start FF7.  Phase 1 runs immediately (just needs the exe loaded).
  2. Run this script.
  3. For Phase 2: enter a battle.  Trigger actions (yours and enemies') and
     watch the logged output.
  4. Press Ctrl+C to stop.
"""

import ctypes
import struct
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"

# ── Static code addresses (no ASLR in 2013 Steam exe) ───────────────────────
FUNC_ADDR = 0x42782A   # display_battle_action_text_42782A — primary hook entry
SUB_ADDR  = 0x6D71FA   # display_battle_action_text_sub_6D71FA (name-derived; Phase 1 verifies)

SCAN_LEN  = 300        # bytes to scan per function (covers full short functions)

# FFNx ff7_data.h: exact byte offsets into FUNC_ADDR's code bytes
#   get_absolute_value(FUNC_ADDR, 0x52) => g_active_actor_id address
#   get_relative_call(FUNC_ADDR, 0x77)  => sub_6D71FA address
ACTOR_ID_CODE_OFFSET = 0x52
SUB_CALL_CODE_OFFSET = 0x77

# ── Battle-state detection ────────────────────────────────────────────────────
# Both external flag approaches were tested and failed:
#   FIELD_ID @ 0xCC15D0      — stays at the field-map ID (e.g. 116) during
#                              random encounters; only 0 on title/world map.
#                              Confirmed empirically: never changed through 2 fights.
#   g_is_battle_running @ 0x9AD1AC — always read 0 through 5 fights at 100 ms poll.
#
# Phase 2 now infers battle state from g_active_actor_id alone:
#   Valid slot (0–2 party, 4–9 enemy)  →  battle action in progress
#   Invalid value (0xFF sentinel / 3 / ≥10)  →  idle or outside battle
# BATTLE_END_TIMEOUT_S of no valid reads → declare battle over.
BATTLE_END_TIMEOUT_S = 5.0   # seconds of consecutive invalid actor before battle-end

# FIELD_ID is kept for reference (the DLL uses it for title-screen filtering,
# but it is NOT a reliable battle gate).
FIELD_ID_ADDR = 0x00CC15D0

# FFNx ff7.h struct field offsets
COMMAND_ID_OFFSET = 0x23   # byte in battle_model_state
ACTION_IDX_OFFSET = 0x3E   # uint16_t in battle_model_state_small

# Struct strides derived from ff7.h definitions:
#   battle_model_state:        last field at 0x1AE8 (uint32) → sizeof = 0x1AEC
#   battle_model_state_small:  last field at 0x73   (byte)   → sizeof = 0x74
BATTLE_MODEL_STATE_STRIDE       = 0x1AEC
BATTLE_MODEL_STATE_SMALL_STRIDE = 0x74

# Tentative base from ff7.h struct comment "characterID // BE1178, 0":
#   actor 0 starts at 0xBE1178 → commandID actor 0 = 0xBE1178 + 0x23 = 0xBE119B
TENTATIVE_G_BATTLE_MODEL_STATE_BASE = 0x00BE1178

# Actor validity ranges (from FFNx voice.cpp actor_id checks):
#   0–2  = party members (Cloud, Barret, Tifa, …)
#   4–9  = enemies (up to 6 in a formation)
#   3, 10–254 = unused / invalid in normal play
#   0xFF = sentinel "no actor" used by some code paths
PARTY_ACTORS = range(0, 3)
ENEMY_ACTORS = range(4, 10)

POLL_MS = 100

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


# ── Output / logging ─────────────────────────────────────────────────────────
class Tee:
    """Write to both terminal and log file simultaneously."""
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file

    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
        self._log.flush()   # flush every write so log survives forced termination

    def flush(self):
        self._terminal.flush()
        self._log.flush()

    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak(text):
    """Fire-and-forget SAPI TTS (async, does not block)."""
    safe = text.replace("'", "''")
    try:
        subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


# ── Process helpers ───────────────────────────────────────────────────────────
def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        if exe_name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def open_process(pid):
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY, False, pid)
    return handle if handle else None


def read_bytes(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    if not ok or read.value != n:
        return None
    return bytes(buf)


def read_u8(handle, addr):
    b = read_bytes(handle, addr, 1)
    return b[0] if b else None


def read_u16(handle, addr):
    b = read_bytes(handle, addr, 2)
    return struct.unpack('<H', b)[0] if b else None


# ── Exe-file helpers (PE parsing) ─────────────────────────────────────────────
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        ctypes.c_ulong),
        ("th32ModuleID",  ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("GlblcntUsage",  ctypes.c_ulong),
        ("ProccntUsage",  ctypes.c_ulong),
        ("modBaseAddr",   ctypes.c_void_p),
        ("modBaseSize",   ctypes.c_ulong),
        ("hModule",       ctypes.c_void_p),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]


def find_module_file_path(pid, module_name):
    """Return the on-disk file path for a named module in the given process."""
    snap = k32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value:
        return None
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    path = None
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            name = me.szModule.decode('ascii', errors='ignore').lower()
            if name == module_name.lower():
                path = me.szExePath.decode('utf-8', errors='replace')
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return path


def va_to_file_offset(exe_data, va, image_base=0x00400000):
    """
    Convert a runtime virtual address to the byte offset in the raw exe file.

    Works by parsing the PE section table.  The image base for all 2013 Steam
    FF7 builds is 0x00400000 (no ASLR).
    """
    rva = va - image_base
    # DOS header: e_lfanew at 0x3C gives offset of IMAGE_NT_HEADERS
    pe_off = struct.unpack_from('<I', exe_data, 0x3C)[0]
    num_sections    = struct.unpack_from('<H', exe_data, pe_off +  6)[0]
    opt_header_size = struct.unpack_from('<H', exe_data, pe_off + 20)[0]
    # Section table starts immediately after the optional header
    sec_off = pe_off + 24 + opt_header_size
    for i in range(num_sections):
        s            = sec_off + i * 40          # IMAGE_SECTION_HEADER is 40 bytes
        virt_size    = struct.unpack_from('<I', exe_data, s +  8)[0]
        virt_addr    = struct.unpack_from('<I', exe_data, s + 12)[0]
        raw_size     = struct.unpack_from('<I', exe_data, s + 16)[0]
        raw_offset   = struct.unpack_from('<I', exe_data, s + 20)[0]
        section_span = max(virt_size, raw_size)
        if virt_addr <= rva < virt_addr + section_span:
            return raw_offset + (rva - virt_addr)
    return None


def read_original_file_bytes(pid, va, length):
    """
    Read raw bytes from the FF7 exe file at the position corresponding to
    virtual address `va`, bypassing any in-memory patches FFNx has applied.

    Returns bytes on success, None if the file cannot be found or the VA
    falls outside the mapped sections.
    """
    path = find_module_file_path(pid, PROCESS_NAME)
    if path is None:
        return None
    try:
        with open(path, 'rb') as f:
            exe_data = f.read()
    except OSError:
        return None
    offset = va_to_file_offset(exe_data, va)
    if offset is None or offset + length > len(exe_data):
        return None
    return exe_data[offset: offset + length]


# ── x86-32 code scanner ───────────────────────────────────────────────────────
# Register name tables for decoding ModRM
REG32 = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
REG8  = ['AL',  'CL',  'DL',  'BL',  'AH',  'CH',  'DH',  'BH']


def scan_code_references(data, base_addr, stop_at_ret=True):
    """
    Linear scan of x86-32 code bytes.  Recognises instructions that embed
    an absolute 32-bit address or a relative call target, plus IMUL immediates
    that reveal struct array strides.

    Patterns handled:
      E8 rel32                CALL rel32
      E9 rel32                JMP  rel32
      A0 abs32                MOV AL,  [abs32]
      A1 abs32                MOV EAX, [abs32]
      8B ModRM abs32          MOV r32, [abs32]   (ModRM mod=00 rm=101)
      8A ModRM abs32          MOV r8,  [abs32]
      89 ModRM abs32          MOV [abs32], r32
      88 ModRM abs32          MOV [abs32], r8
      6B ModRM imm8           IMUL r32, r/m32, imm8  (≤8-bit struct stride)
      69 ModRM imm32          IMUL r32, r/m32, imm32 (>8-bit struct stride)
      FF 15 abs32             CALL [abs32]
      68 imm32                PUSH imm32
      C3 / CB / C2 nn nn      RET  (stops scan if stop_at_ret=True)

    Returns list of (instr_offset, mnemonic, value, note).
    """
    results = []
    i = 0
    n = len(data)

    while i < n - 4:
        b = data[i]

        # ── RET: function boundary ──────────────────────────────────────────
        if stop_at_ret and b in (0xC3, 0xCB):
            results.append((i, 'RET', 0, 'function end'))
            break
        if stop_at_ret and b == 0xC2 and i + 2 < n:
            ret_n = struct.unpack_from('<H', data, i + 1)[0]
            results.append((i, f'RET {ret_n}', 0, 'function end'))
            break

        # ── CALL rel32 ──────────────────────────────────────────────────────
        if b == 0xE8 and i + 5 <= n:
            rel    = struct.unpack_from('<i', data, i + 1)[0]
            target = base_addr + i + 5 + rel
            results.append((i, 'CALL rel32', target, ''))
            i += 5
            continue

        # ── JMP rel32 ───────────────────────────────────────────────────────
        if b == 0xE9 and i + 5 <= n:
            rel    = struct.unpack_from('<i', data, i + 1)[0]
            target = base_addr + i + 5 + rel
            results.append((i, 'JMP rel32', target, ''))
            i += 5
            continue

        # ── MOV AL / EAX, [abs32] (short encodings) ─────────────────────────
        if b == 0xA0 and i + 5 <= n:
            addr = struct.unpack_from('<I', data, i + 1)[0]
            results.append((i, 'MOV AL,[abs32]', addr, ''))
            i += 5
            continue
        if b == 0xA1 and i + 5 <= n:
            addr = struct.unpack_from('<I', data, i + 1)[0]
            results.append((i, 'MOV EAX,[abs32]', addr, ''))
            i += 5
            continue

        # ── MOV r32/r8, [abs32]  and  MOV [abs32], r32/r8 ──────────────────
        # ModRM byte with mod=00, rm=101 embeds a 32-bit absolute address.
        # (ModRM & 0xC7) == 0x05 is the distinguishing condition.
        if b in (0x8B, 0x8A, 0x89, 0x88) and i + 6 <= n:
            modrm = data[i + 1]
            if (modrm & 0xC7) == 0x05:
                addr = struct.unpack_from('<I', data, i + 2)[0]
                reg  = (modrm >> 3) & 7
                if b == 0x8B:
                    mnem = f'MOV {REG32[reg]},[abs32]'
                elif b == 0x8A:
                    mnem = f'MOV {REG8[reg]},[abs32]'
                elif b == 0x89:
                    mnem = f'MOV [abs32],{REG32[reg]}'
                else:
                    mnem = f'MOV [abs32],{REG8[reg]}'
                results.append((i, mnem, addr, ''))
                i += 6
                continue

        # ── CALL [abs32] — FF 15 abs32 ──────────────────────────────────────
        if b == 0xFF and i + 6 <= n and data[i + 1] == 0x15:
            addr = struct.unpack_from('<I', data, i + 2)[0]
            results.append((i, 'CALL [abs32]', addr, ''))
            i += 6
            continue

        # ── IMUL r32, r/m32, imm8 — 6B /r ib ───────────────────────────────
        # imm8 reveals struct array stride when < 256.
        if b == 0x6B and i + 3 <= n:
            modrm = data[i + 1]
            mod   = (modrm >> 6) & 3
            rm    = modrm & 7
            reg   = (modrm >> 3) & 7
            imm8  = data[i + 2]
            note  = f'possible stride={imm8:#x} ({imm8})'
            results.append((i, f'IMUL {REG32[reg]},r/m,{imm8:#04x}', imm8, note))
            if mod == 3:
                i += 3
            elif mod == 0 and rm == 5:
                i += 8   # 1(op) + 1(ModRM) + 4(abs32) + 1(imm8) + pad
            elif mod == 1:
                i += 4   # 1 + 1 + 1(disp8) + 1(imm8)
            elif mod == 2:
                i += 8   # 1 + 1 + 4(disp32) + 1(imm8) + pad
            else:
                i += 3
            continue

        # ── IMUL r32, r/m32, imm32 — 69 /r id ──────────────────────────────
        # Used when stride > 255 (e.g. battle_model_state stride = 0x1AEC).
        if b == 0x69 and i + 6 <= n:
            modrm = data[i + 1]
            mod   = (modrm >> 6) & 3
            reg   = (modrm >> 3) & 7
            if mod == 3:   # register operand: 69 /r id (6 bytes total)
                imm32 = struct.unpack_from('<I', data, i + 2)[0]
                note  = f'possible stride={imm32:#x} ({imm32})'
                results.append((i, f'IMUL {REG32[reg]},r,{imm32:#010x}', imm32, note))
                i += 6
                continue

        # ── MOV r32, imm32 — opcodes B8–BF ─────────────────────────────────
        # Compilers often embed array base addresses as a MOV r32, imm32 before
        # an ADD + index computation.  Addresses in the FF7 BSS range are flagged.
        if 0xB8 <= b <= 0xBF and i + 5 <= n:
            reg   = b - 0xB8
            imm32 = struct.unpack_from('<I', data, i + 1)[0]
            results.append((i, f'MOV {REG32[reg]},imm32', imm32, ''))
            i += 5
            continue

        # ── ADD EAX, imm32 — 05 imm32 ───────────────────────────────────────
        # Often follows IMUL to add the array base to the scaled index.
        if b == 0x05 and i + 5 <= n:
            imm32 = struct.unpack_from('<I', data, i + 1)[0]
            results.append((i, 'ADD EAX,imm32', imm32, ''))
            i += 5
            continue

        # ── PUSH imm32 — 68 imm32 ───────────────────────────────────────────
        # Often used to push constants; may be an address if in code/data range.
        if b == 0x68 and i + 5 <= n:
            imm32 = struct.unpack_from('<I', data, i + 1)[0]
            results.append((i, 'PUSH imm32', imm32, ''))
            i += 5
            continue

        i += 1

    return results


def print_scan(results, base_addr, label, highlight=None):
    """
    Print code scan results.
    highlight: dict of {byte_offset: annotation_string} for marking key offsets.
    """
    highlight = highlight or {}
    print(f"\n  {'─'*70}")
    print(f"  {label}  (base=0x{base_addr:08X})")
    print(f"  {'─'*70}")
    print(f"  {'Offset':<8}  {'Abs addr':<12}  {'Mnemonic':<30}  {'Value':<12}  Notes")
    print(f"  {'------':<8}  {'--------':<12}  {'--------':<30}  {'-----':<12}  -----")
    for offset, mnem, value, note in results:
        ann = highlight.get(offset, '')
        if ann:
            note = f'◄ {ann}' + (f'  [{note}]' if note else '')
        if 'RET' in mnem or value == 0:
            print(f"  +{offset:#06x}  {base_addr+offset:#012x}  {mnem:<30}  {'':12}  {note}")
        else:
            print(f"  +{offset:#06x}  {base_addr+offset:#012x}  {mnem:<30}  {value:#012x}  {note}")


# ── Phase 1: address discovery ────────────────────────────────────────────────
def phase1_discover(handle, pid):
    """
    Read code at FUNC_ADDR and SUB_ADDR, scan for data references and call
    targets, extract the key addresses the monitor loop needs.

    `pid` is needed to locate the FF7 exe file for the on-disk scan in Step 5.

    Returns a dict with keys:
      'actor_id_addr'          — address of g_active_actor_id byte
      'sub_6D71FA_addr'        — address of display_battle_action_text_sub_6D71FA
      'model_state_base'       — base of g_battle_model_state array (or tentative)
      'model_state_small_base' — base of g_small_battle_model_state array (or None)
      'model_state_stride'     — sizeof(battle_model_state) from IMUL
      'model_state_small_stride' — sizeof(battle_model_state_small) from IMUL
      'get_kernel_text_addr'   — confirmed address from exe-file scan, or None
      'get_kernel_text_candidates' — CALL targets from in-memory scan (may be FFNx)
    """
    addrs = {
        'actor_id_addr':             None,
        'sub_6D71FA_addr':           None,
        'model_state_base':          TENTATIVE_G_BATTLE_MODEL_STATE_BASE,
        'model_state_small_base':    None,
        'model_state_stride':        BATTLE_MODEL_STATE_STRIDE,
        'model_state_small_stride':  BATTLE_MODEL_STATE_SMALL_STRIDE,
        'get_kernel_text_addr':       None,
        'get_kernel_text_candidates': [],
    }

    # ── Step 1: Read g_active_actor_id address (abs32 at FUNC_ADDR+0x52) ────
    print(f"\n  Deriving g_active_actor_id from FUNC_ADDR+{ACTOR_ID_CODE_OFFSET:#x}...")
    actor_id_addr_bytes = read_bytes(handle, FUNC_ADDR + ACTOR_ID_CODE_OFFSET, 4)
    if actor_id_addr_bytes is None:
        print("  ERROR: could not read 4 bytes at FUNC_ADDR+0x52")
    else:
        addrs['actor_id_addr'] = struct.unpack('<I', actor_id_addr_bytes)[0]
        print(f"  g_active_actor_id addr = 0x{addrs['actor_id_addr']:08X}")

    # ── Step 2: Verify sub_6D71FA address (CALL rel32 at FUNC_ADDR+0x77) ───
    # get_relative_call(FUNC_ADDR, 0x77):  target = FUNC_ADDR+0x77+5 + *(int32*)(FUNC_ADDR+0x78)
    print(f"\n  Verifying sub_6D71FA address from CALL at FUNC_ADDR+{SUB_CALL_CODE_OFFSET:#x}...")
    call_rel_bytes = read_bytes(handle, FUNC_ADDR + SUB_CALL_CODE_OFFSET + 1, 4)
    if call_rel_bytes is None:
        print("  ERROR: could not read relative offset at FUNC_ADDR+0x78")
        addrs['sub_6D71FA_addr'] = SUB_ADDR  # fall back to name-derived value
    else:
        rel     = struct.unpack('<i', call_rel_bytes)[0]
        target  = FUNC_ADDR + SUB_CALL_CODE_OFFSET + 5 + rel
        addrs['sub_6D71FA_addr'] = target
        match = "✓ matches name-derived" if target == SUB_ADDR else f"✗ MISMATCH! expected 0x{SUB_ADDR:08X}"
        print(f"  sub_6D71FA addr = 0x{target:08X}  {match}")

    # ── Step 3: Full scan of FUNC_ADDR ──────────────────────────────────────
    func_data = read_bytes(handle, FUNC_ADDR, SCAN_LEN)
    if func_data is None:
        print(f"\n  ERROR: could not read {SCAN_LEN} bytes at FUNC_ADDR=0x{FUNC_ADDR:08X}")
    else:
        refs = scan_code_references(func_data, FUNC_ADDR)
        highlight = {
            ACTOR_ID_CODE_OFFSET: 'g_active_actor_id abs32',
            SUB_CALL_CODE_OFFSET: 'CALL → sub_6D71FA',
        }
        print_scan(refs, FUNC_ADDR, 'display_battle_action_text_42782A', highlight)

        # Collect all absolute addresses found in data-referencing instructions.
        # This covers MOV [abs32] patterns, MOV r32,imm32, and ADD EAX,imm32 —
        # all idioms the compiler uses to embed array/global addresses.
        data_refs = [v for (off, m, v, _) in refs
                     if ('[abs32]' in m or 'imm32' in m)
                     and v > 0x00400000 and v < 0x01000000]

        # Collect IMUL strides
        for offset, mnem, value, note in refs:
            if 'IMUL' in mnem and value > 0:
                if value == BATTLE_MODEL_STATE_STRIDE:
                    print(f"\n  ★ IMUL at +{offset:#x} matches expected battle_model_state"
                          f" stride 0x{BATTLE_MODEL_STATE_STRIDE:X}")
                    addrs['model_state_stride'] = value
                elif value == BATTLE_MODEL_STATE_SMALL_STRIDE:
                    print(f"\n  ★ IMUL at +{offset:#x} matches expected battle_model_state_small"
                          f" stride 0x{BATTLE_MODEL_STATE_SMALL_STRIDE:X}")
                    addrs['model_state_small_stride'] = value
                else:
                    print(f"\n  ? IMUL at +{offset:#x} with stride {value:#x} ({value})"
                          f" — investigate if this is a struct index")

        # Identify array bases from the data refs by excluding actor_id_addr
        # and looking for candidates in the ~0x00BE0000–0x00C00000 range
        # where battle state lives.
        print(f"\n  Data refs in FUNC_ADDR (sorted):")
        for addr in sorted(set(data_refs)):
            tag = ''
            if addrs['actor_id_addr'] and addr == addrs['actor_id_addr']:
                tag = '← g_active_actor_id'
            elif 0x00B00000 <= addr <= 0x00D00000:
                tag = '← possible model-state array base or field'
            print(f"    0x{addr:08X}  {tag}")

        # Annotate candidates near the tentative g_battle_model_state base (0xBE1178).
        # The embedded value may be the array base itself OR base+field_offset depending
        # on how the compiler generates the indexed access.  We flag anything within
        # ±0x100 of the tentative base and let the full scan output confirm which is which.
        #
        # Definitive identification requires reading the IMUL stride and seeing what
        # follows it in the disassembly — that's what the printed scan table is for.
        battle_range_refs = sorted(
            a for a in set(data_refs)
            if 0x00B00000 <= a <= 0x00D00000
            and (addrs['actor_id_addr'] is None or a != addrs['actor_id_addr'])
        )
        if battle_range_refs:
            for candidate in battle_range_refs:
                delta_from_base    = candidate - TENTATIVE_G_BATTLE_MODEL_STATE_BASE
                delta_from_cmd_id  = candidate - (TENTATIVE_G_BATTLE_MODEL_STATE_BASE
                                                   + COMMAND_ID_OFFSET)
                if abs(delta_from_base) < 0x100:
                    print(f"\n  ★ 0x{candidate:08X}"
                          f"  delta from tentative base 0x{TENTATIVE_G_BATTLE_MODEL_STATE_BASE:08X}"
                          f" = {delta_from_base:+#x}")
                    if delta_from_base == 0:
                        # Instruction embeds the raw base — base is the candidate itself
                        addrs['model_state_base'] = candidate
                        print(f"    → embedded as raw base; model_state_base = 0x{candidate:08X}")
                    elif delta_from_cmd_id == 0:
                        # Instruction embeds base+0x23 (commandID addr for actor 0)
                        addrs['model_state_base'] = candidate - COMMAND_ID_OFFSET
                        print(f"    → embedded as base+{COMMAND_ID_OFFSET:#x};"
                              f" model_state_base = 0x{addrs['model_state_base']:08X}")
                    else:
                        # Unexpected offset — print both interpretations for manual review
                        print(f"    → unexpected delta; could be base"
                              f" or base+{delta_from_base:#x}; check scan table")
                        addrs['model_state_base'] = candidate  # best guess
                    break

            # Any remaining battle-range ref is tentatively g_small_battle_model_state.
            # Same ambiguity applies: we don't know if it's embedded as base or base+field.
            # Just flag it; the DLL implementation will confirm via Phase 2 monitor output.
            for candidate in battle_range_refs:
                if addrs['model_state_base'] and \
                   abs(candidate - addrs['model_state_base']) < 0x100:
                    continue  # same array already identified above
                if addrs['model_state_small_base'] is None:
                    print(f"\n  ★ 0x{candidate:08X} — possible g_small_battle_model_state"
                          f" base or base+field; actionIdx is at +{ACTION_IDX_OFFSET:#x}"
                          f" within that struct")
                    addrs['model_state_small_base'] = candidate
                    break

    # ── Step 4: Full scan of sub_6D71FA ─────────────────────────────────────
    sub_addr = addrs['sub_6D71FA_addr'] or SUB_ADDR
    sub_data  = read_bytes(handle, sub_addr, SCAN_LEN)
    if sub_data is None:
        print(f"\n  ERROR: could not read {SCAN_LEN} bytes at sub addr 0x{sub_addr:08X}")
    else:
        sub_refs = scan_code_references(sub_data, sub_addr)
        print_scan(sub_refs, sub_addr, 'display_battle_action_text_sub_6D71FA')

        # All CALL targets within sub_6D71FA are candidates for get_kernel_text.
        # Note: if sub_6D71FA has been trampolined by FFNx, targets here land in
        # FFNx's code, not the original FF7 get_kernel_text.  Step 5 reads the
        # original file to find the real address.
        call_targets = [(off, v) for (off, m, v, _) in sub_refs if 'CALL rel32' in m]
        addrs['get_kernel_text_candidates'] = [v for _, v in call_targets]
        if call_targets:
            print(f"\n  CALL targets in sub_6D71FA in-memory (may be FFNx code):")
            for off, target in call_targets:
                print(f"    +{off:#06x}  →  0x{target:08X}")
        else:
            print(f"\n  No CALL rel32 found in sub_6D71FA — check scan range or verify address")

    # ── Step 5: Scan original exe file for get_kernel_text ───────────────────
    # FFNx patches code in memory but not on disk.  Reading the exe file gives
    # us the original bytes at sub_6D71FA, from which we can extract the real
    # CALL rel32 target = get_kernel_text.
    print(f"\n  ──────────────────────────────────────────────────────────────────────")
    print(f"  sub_6D71FA [ORIGINAL FILE]  (reading ff7_en.exe from disk)")
    print(f"  ──────────────────────────────────────────────────────────────────────")
    orig_bytes = read_original_file_bytes(pid, SUB_ADDR, 64)
    if orig_bytes is None:
        print(f"  ERROR: could not read original exe bytes at VA 0x{SUB_ADDR:08X}")
        print(f"  (ff7_en.exe path could not be found, or VA not in any PE section)")
    else:
        orig_refs = scan_code_references(orig_bytes, SUB_ADDR)
        print_scan(orig_refs, SUB_ADDR, 'sub_6D71FA [original]')
        orig_calls = [(off, v) for (off, m, v, _) in orig_refs if 'CALL rel32' in m]
        if orig_calls:
            print(f"\n  ★ get_kernel_text (from original file):")
            for off, target in orig_calls:
                print(f"      +{off:#06x}  →  0x{target:08X}")
            if len(orig_calls) == 1:
                addrs['get_kernel_text_addr'] = orig_calls[0][1]
                print(f"  ★ Single CALL found — confirmed as get_kernel_text = 0x{addrs['get_kernel_text_addr']:08X}")
            else:
                print(f"  Multiple CALLs — review which is get_kernel_text")
        else:
            print(f"  No CALL rel32 found in original sub_6D71FA bytes")

    return addrs


# ── Phase 2: live monitor ─────────────────────────────────────────────────────
def actor_label(actor_id):
    """Return a human-readable label for an actor slot."""
    # Party slot → character name by conventional FF7 index
    # (Cloud=0, Barret=1, Tifa=2, Aeris=3, Red XIII=4, Yuffie=5, Cait Sith=6,
    #  Vincent=7, Cid=8) — but actor slot 0-2 is whoever is currently in the party.
    party_names = ['Cloud', 'Barret', 'Tifa', 'Aeris', 'Red XIII',
                   'Yuffie', 'Cait Sith', 'Vincent', 'Cid']
    if actor_id in PARTY_ACTORS:
        return f'party slot {actor_id}'
    if actor_id in ENEMY_ACTORS:
        return f'enemy slot {actor_id}'
    return f'actor {actor_id:#x} (unexpected)'


def actor_is_valid(actor_id):
    """Return True for actor slots that exist in a battle formation."""
    return actor_id is not None and (actor_id in PARTY_ACTORS or actor_id in ENEMY_ACTORS)


def phase2_monitor(handle, addrs):
    """
    Poll g_active_actor_id and report every battle action.

    Battle detection uses commandID as the real gate, not actor_id alone.
    g_active_actor_id initialises to 0 at process start (Cloud's party slot)
    and is never reset between battles — it retains the last acting actor's
    slot number throughout.  A bare actor_id check therefore triggers a false
    'BATTLE STARTED' at script launch.

    A "real action" requires BOTH:
      - actor_id is a valid battle slot (0–2 party, 4–9 enemy)
      - commandID for that slot is non-zero (the model-state struct is zeroed
        at startup; commandID becomes non-zero only when the battle engine sets
        up an action)

    State machine:
      - Real action after being out-of-battle → BATTLE STARTED (then report action)
      - Actor slot changes AND new slot's commandID != 0 → report action
      - BATTLE_END_TIMEOUT_S seconds since last real action → BATTLE ENDED
        (actor_id never resets to invalid, so timeout is the only end signal;
        30 s exceeds any normal between-turn gap in early-game ATB battles)
    """
    actor_id_addr = addrs['actor_id_addr']
    if actor_id_addr is None:
        print("\n  ERROR: g_active_actor_id address not found in Phase 1; cannot monitor")
        return

    model_base   = addrs['model_state_base']
    model_stride = addrs['model_state_stride']
    small_base   = addrs['model_state_small_base']
    small_stride = addrs['model_state_small_stride']

    print(f"\n  Monitoring g_active_actor_id @ 0x{actor_id_addr:08X}")
    print(f"  Battle gate: actor_id valid AND commandID != 0")
    if model_base:
        print(f"  g_battle_model_state       base=0x{model_base:08X}"
              f"  stride=0x{model_stride:X}  commandID @ +{COMMAND_ID_OFFSET:#x}")
    else:
        print(f"  g_battle_model_state base not found — commandID will not be read")
    if small_base:
        print(f"  g_small_battle_model_state base=0x{small_base:08X}"
              f"  stride=0x{small_stride:X}  actionIdx @ +{ACTION_IDX_OFFSET:#x}")
    else:
        print(f"  g_small_battle_model_state base not found — actionIdx will not be read")

    print(f"\n  Walk around the field until a random battle starts.")
    print(f"  Script will announce 'battle started' and begin logging actions.")
    print(f"  Ctrl+C to stop.")
    speak("Phase 2 ready. Walk around until a battle starts.")
    print()

    in_battle          = False
    last_actor         = None
    last_action_time   = None   # monotonic time of last real action (commandID != 0)

    while True:
        time.sleep(POLL_MS / 1000.0)
        now  = time.strftime('%H:%M:%S')
        mono = time.monotonic()

        actor_id = read_u8(handle, actor_id_addr)
        if actor_id is None:
            print(f"  {now}  WARNING: could not read g_active_actor_id")
            continue

        # ── Read commandID for the current actor slot ─────────────────────────
        command_id = None
        if model_base is not None and actor_is_valid(actor_id):
            addr = model_base + actor_id * model_stride + COMMAND_ID_OFFSET
            command_id = read_u8(handle, addr)

        real_action = actor_is_valid(actor_id) and command_id is not None and command_id != 0

        # ── Battle-end timeout ────────────────────────────────────────────────
        # Actor_id never resets to invalid between battles, so we rely on
        # "no real action seen for BATTLE_END_TIMEOUT_S seconds".
        if in_battle and not real_action:
            if last_action_time is not None and (mono - last_action_time) >= BATTLE_END_TIMEOUT_S:
                in_battle       = False
                last_actor      = None
                last_action_time = None
                print(f"  {now}  *** BATTLE ENDED — waiting for next encounter ***")
                speak("Battle ended.")
            continue

        if not real_action:
            continue   # on field, commandID == 0 or actor slot invalid

        # ── Battle start ──────────────────────────────────────────────────────
        if not in_battle:
            in_battle      = True
            last_actor     = None
            last_action_time = mono
            print(f"  {now}  *** BATTLE STARTED ***")
            speak("Battle started.")
            # Fall through to report this first action immediately.

        last_action_time = mono   # refresh timeout clock on every real action

        if actor_id == last_actor:
            continue   # same slot acting again (repeated action, already reported)
        last_actor = actor_id

        label = actor_label(actor_id)

        # ── Read actionIdx for this actor ─────────────────────────────────────
        # NOTE: small_base from Phase 1 may be the raw array base OR base+field,
        # depending on which instruction the heuristic matched.  If actionIdx
        # values look implausible (e.g. always 0xFFFF), the small_base address
        # may need ±ACTION_IDX_OFFSET adjustment — see Phase 1 scan table.
        action_idx = None
        if small_base is not None:
            addr = small_base + actor_id * small_stride + ACTION_IDX_OFFSET
            b    = read_bytes(handle, addr, 2)
            if b:
                action_idx = struct.unpack('<H', b)[0]

        # ── Log and speak ─────────────────────────────────────────────────────
        parts = [f"actor_id={actor_id:#04x}  ({label})"]
        parts.append(f"commandID={command_id:#04x} ({command_id})")
        parts.append(f"actionIdx={action_idx:#06x} ({action_idx})" if action_idx is not None
                     else "actionIdx=?")
        print(f"  {now}  " + "  ".join(parts))

        summary = f"{label} acting"
        summary += f", command {command_id}"
        if action_idx is not None:
            summary += f", action {action_idx}"
        speak(summary)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"battle_action_scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Battle Action Scan")
        print("Discovers battle action text addresses; monitors live during battle.")
        print()

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            print("ERROR: ff7_en.exe not running.  Start FF7 first.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            print("ERROR: OpenProcess failed.")
            return

        # ── Phase 1 ─────────────────────────────────────────────────────────
        print()
        print("=" * 72)
        print("  PHASE 1 — ADDRESS DISCOVERY")
        print("=" * 72)
        addrs = phase1_discover(handle, pid)

        print()
        print("=" * 72)
        print("  PHASE 1 SUMMARY")
        print("=" * 72)
        print(f"  g_active_actor_id addr     : "
              f"{'0x'+format(addrs['actor_id_addr'],'08X') if addrs['actor_id_addr'] else 'NOT FOUND'}")
        print(f"  sub_6D71FA addr verified   : "
              f"{'0x'+format(addrs['sub_6D71FA_addr'],'08X') if addrs['sub_6D71FA_addr'] else 'NOT FOUND'}")
        print(f"  g_battle_model_state base  : "
              f"0x{addrs['model_state_base']:08X}"
              f"  (stride=0x{addrs['model_state_stride']:X})"
              if addrs['model_state_base'] else "  g_battle_model_state base  : NOT FOUND")
        print(f"  g_small_battle_model_state : "
              f"0x{addrs['model_state_small_base']:08X}"
              f"  (stride=0x{addrs['model_state_small_stride']:X})"
              if addrs['model_state_small_base'] else
              "  g_small_battle_model_state : NOT FOUND")
        gkt = addrs.get('get_kernel_text_addr')
        if gkt:
            print(f"  get_kernel_text (from file) : 0x{gkt:08X}  ← use this in ff7_addresses.h")
        elif addrs['get_kernel_text_candidates']:
            print(f"  get_kernel_text (in-memory) : "
                  + ", ".join(f"0x{a:08X}" for a in addrs['get_kernel_text_candidates'])
                  + "  ← WARNING: may be FFNx code")
        else:
            print(f"  get_kernel_text             : NOT FOUND")

        print()
        print("  NEXT STEPS (after reviewing this output):")
        print("  1. Run Phase 2 and trigger battle actions to confirm commandID and")
        print("     actionIdx values change sensibly per action.")
        print("  2. Note: get_kernel_text candidate 0x016E4E3C is from FFNx's")
        print("     trampolined code (both 0x42782A and 0x6D71FA start with FFNx JMP).")
        print("     The real FF7 get_kernel_text must be found via an unpatched path.")
        print("  3. Once commandID/actionIdx confirmed, add addresses to ff7_addresses.h")
        print("     and implement the hook in proxy.cpp.")
        print()

        # ── Phase 2 ─────────────────────────────────────────────────────────
        print("=" * 72)
        print("  PHASE 2 — LIVE MONITOR")
        print("=" * 72)
        phase2_monitor(handle, addrs)

    except KeyboardInterrupt:
        print()
        print("  [Stopped by user]")
        speak("Battle scan stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        print(f"\nLog saved to: {log_path}")
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
