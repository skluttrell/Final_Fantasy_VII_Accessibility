#!/usr/bin/env python3
"""
ff7_wall_nav_static.py — Static resolution of field-navigation addresses
=========================================================================

PURPOSE
-------
Resolve, from the ff7_en.exe file ON DISK (no running game needed), the
absolute addresses required for the wall-bump navigation tone feature:

    1. modules_global_object   — the field module's global state struct.
       Contains current_key_input_status (u32) at +0x68: the digested
       controller/keyboard input bitmask the field engine actually consumes
       (UP=0x1000, RIGHT=0x2000, DOWN=0x4000, LEFT=0x8000, per FFNx's
       ff7::world::input_key enum, shared digest format across modules).
       Expected value: 0xCC0D88 (comment in FFNx ff7.h line 3186).

    2. field_event_data_ptr    — global that points to the heap-allocated
       array of per-entity field_event_data structs (0x88 bytes each).
       model_pos (3 x int32 world coordinates) lives at +0x0C in each
       element. Expected value: 0xCC0B60 (comment in FFNx ff7.h line 3182).

    3. field_player_model_id   — global short holding the index of the
       PLAYER's model within that array (the player is not always model 0;
       fields load models in file order). No known expected value — this
       is the one address we cannot get from an FFNx comment.

    4. field_n_models          — global WORD, number of models on the
       current field. Useful as a bounds sanity check when polling.

WHY STATIC FILE ANALYSIS (not live memory)
------------------------------------------
FFNx trampolines many field functions at runtime (it replaces
field_update_models_positions call sites for its 60FPS interpolation),
so reading the LIVE code bytes risks reading FFNx's patched instructions.
The exe file on disk contains only original Square code. There is no ASLR
on this binary (image base 0x400000, fixed), so file-derived VAs are the
run-time VAs.

RESOLUTION CHAINS (all lifted verbatim from FFNx/src/ff7_data.h)
----------------------------------------------------------------
    field_init_event_60BACF = 0x60BACF          (known anchor, same one
                                                 our mod's Resolve() uses)
    execute_opcode          = get_relative_call(field_init_event, 0x80)
    execute_opcode_table    = get_absolute_value(execute_opcode, 0x10D)
    opcode_canm1_canm2      = execute_opcode_table[0xB1]   (CANM1 handler)
    field_event_data_ptr    = get_absolute_value(opcode_canm1_canm2, 0xC1)
    modules_global_object   = get_absolute_value(field_init_event, 0x20)

    field_loop_sub_63C17F        = 0x63C17F     (FFNx name = absolute VA)
    field_update_models_positions = get_relative_call(field_loop, 0x5DD)
    field_player_model_id   = get_absolute_value(update_models_pos, 0x45D)
    field_n_models          = get_absolute_value(update_models_pos, 0x25)

get_relative_call / get_absolute_value semantics (FFNx patch.cpp):
    get_relative_call(base, off):  E8 rel32 at base+off →
                                   target = base + off + 5 + rel32
                                   (5 = 1 opcode byte + 4 operand bytes)
    get_absolute_value(base, off): u32 read directly at base+off
                                   (off points AT the imm32 operand,
                                    not at the instruction start)

USAGE
-----
    python ff7_wall_nav_static.py

No game required. Reads the exe from the 2013 Steam path, the 2026
rerelease workingdir path, or a running ff7_en.exe process's module path,
whichever is found first.
"""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
import time

IMAGE_BASE = 0x400000

# Known anchors (2013 Steam / 1.02 US exe; confirmed identical in the 2026
# rerelease's bundled ff7_en binary).
FIELD_INIT_EVENT   = 0x60BACF
FIELD_LOOP_63C17F  = 0x63C17F

# Expected values from FFNx ff7.h source comments — used as cross-checks.
EXPECT_MODULES_GLOBAL_OBJECT = 0xCC0D88
EXPECT_FIELD_EVENT_DATA_PTR  = 0xCC0B60

# Candidate exe locations, tried in order.
EXE_CANDIDATES = [
    # 2013 Steam release (flat layout, exe in game root)
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    # 2026 rerelease (exe manually copied into workingdir for modded play)
    r"C:\Program Files (x86)\Steam\steamapps\common\Final Fantasy VII Steam Edition\ff7\workingdir\ff7_en.exe",
    # 2026 rerelease pristine copy (no .exe extension in resources folder)
    r"C:\Program Files (x86)\Steam\steamapps\common\Final Fantasy VII Steam Edition\ff7\resources\ff7_1.02\ff7_en",
]


# ---------------------------------------------------------------------------
# Output tee: mirror all print() output to a timestamped log file so the
# session is recorded automatically (project rule — never require manual
# copy-paste of terminal output).
# ---------------------------------------------------------------------------
class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file
    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
    def flush(self):
        self._terminal.flush()
        self._log.flush()
    def __getattr__(self, name):
        return getattr(self._terminal, name)


# ---------------------------------------------------------------------------
# PE file parsing: map a virtual address to a file offset via section table.
# The exe is not ASLR'd, so VA == IMAGE_BASE + RVA at run time.
# ---------------------------------------------------------------------------
def parse_pe_sections(exe_data):
    pe_off  = struct.unpack_from('<I', exe_data, 0x3C)[0]
    nsec    = struct.unpack_from('<H', exe_data, pe_off +  6)[0]
    oph_sz  = struct.unpack_from('<H', exe_data, pe_off + 20)[0]
    sec_off = pe_off + 24 + oph_sz
    sections = []
    for i in range(nsec):
        s      = sec_off + i * 40
        name   = exe_data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsz    = struct.unpack_from('<I', exe_data, s +  8)[0]
        va     = struct.unpack_from('<I', exe_data, s + 12)[0]
        rawsz  = struct.unpack_from('<I', exe_data, s + 16)[0]
        rawoff = struct.unpack_from('<I', exe_data, s + 20)[0]
        sections.append((name, va, vsz, rawoff, rawsz))
    return sections


def va_to_file_offset(exe_data, va):
    rva      = va - IMAGE_BASE
    for (name, virt_addr, virt_size, raw_offset, raw_size) in parse_pe_sections(exe_data):
        # Use the larger of virtual/raw size: BSS-style sections have
        # virt_size > raw_size and reads there would be invalid anyway,
        # but initialized data (like the opcode table) is fully backed.
        span = max(virt_size, raw_size)
        if virt_addr <= rva < virt_addr + span:
            return raw_offset + (rva - virt_addr)
    return None


def read_u8(exe_data, va):
    off = va_to_file_offset(exe_data, va)
    if off is None or off >= len(exe_data):
        return None
    return exe_data[off]


def read_u32(exe_data, va):
    off = va_to_file_offset(exe_data, va)
    if off is None or off + 4 > len(exe_data):
        return None
    return struct.unpack_from('<I', exe_data, off)[0]


# ---------------------------------------------------------------------------
# FFNx-equivalent resolution primitives, operating on the file image.
# ---------------------------------------------------------------------------
def get_relative_call(exe_data, base, offset):
    """Replicates FFNx get_relative_call for a plain E8 rel32 CALL.

    Verifies the opcode byte really is E8 — if FFNx's offset constant did not
    line up with a CALL in this build, we must fail loudly rather than return
    a garbage address (this is exactly the scanner false-positive class that
    burned the earlier get_kernel_text investigation)."""
    opcode = read_u8(exe_data, base + offset)
    if opcode != 0xE8:
        return None, f"expected E8 CALL at {base + offset:#010x}, found {opcode:#04x}" \
                     if opcode is not None else "address unmapped in file"
    rel = read_u32(exe_data, base + offset + 1)
    if rel is None:
        return None, "rel32 operand unmapped in file"
    # Sign-extend and compute target: address-after-instruction + rel32.
    if rel >= 0x80000000:
        rel -= 0x100000000
    return (base + offset + 5 + rel) & 0xFFFFFFFF, None


def get_absolute_value(exe_data, base, offset):
    """Replicates FFNx get_absolute_value: u32 at base+offset (the offset
    points directly at an imm32/disp32 operand inside an instruction)."""
    val = read_u32(exe_data, base + offset)
    if val is None:
        return None, "address unmapped in file"
    return val, None


def load_exe():
    for path in EXE_CANDIDATES:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return f.read(), path
    return None, None


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path   = os.path.join(
        script_dir, f"wall_nav_static_{time.strftime('%Y%m%d_%H%M%S')}.log")
    real_stdout = sys.stdout
    log_file    = open(log_path, 'w', encoding='utf-8')
    sys.stdout  = Tee(real_stdout, log_file)
    try:
        print(f"Log: {log_path}")
        print("=" * 70)
        print("FF7 wall-navigation static address resolution")
        print("=" * 70)

        exe_data, exe_path = load_exe()
        if exe_data is None:
            print("ERROR: ff7_en.exe not found at any known location:")
            for p in EXE_CANDIDATES:
                print(f"  - {p}")
            return 1
        print(f"Loaded exe: {exe_path}  ({len(exe_data):,} bytes)")
        print()

        failures = []

        # --- modules_global_object -------------------------------------
        mgo, err = get_absolute_value(exe_data, FIELD_INIT_EVENT, 0x20)
        print(f"modules_global_object       = "
              f"{mgo:#010x}" if mgo is not None else f"FAILED: {err}")
        if mgo != EXPECT_MODULES_GLOBAL_OBJECT:
            failures.append(
                f"modules_global_object {mgo:#x} != expected "
                f"{EXPECT_MODULES_GLOBAL_OBJECT:#x}")
        else:
            print(f"  MATCHES FFNx ff7.h comment ({EXPECT_MODULES_GLOBAL_OBJECT:#x}) — "
                  f"current_key_input_status at +0x68 = {mgo + 0x68:#010x}")

        # --- execute_opcode_table → CANM1 → field_event_data_ptr --------
        execute_opcode, err = get_relative_call(exe_data, FIELD_INIT_EVENT, 0x80)
        if execute_opcode is None:
            print(f"execute_opcode              = FAILED: {err}")
            failures.append(f"execute_opcode: {err}")
        else:
            print(f"execute_opcode              = {execute_opcode:#010x}")
            table, err = get_absolute_value(exe_data, execute_opcode, 0x10D)
            if table is None:
                print(f"execute_opcode_table        = FAILED: {err}")
                failures.append(f"execute_opcode_table: {err}")
            else:
                print(f"execute_opcode_table        = {table:#010x}")
                canm, err = get_absolute_value(exe_data, table + 0xB1 * 4, 0)
                if canm is None or not (0x401000 <= canm <= 0x9FFFFF):
                    print(f"opcode_canm1_canm2          = FAILED "
                          f"({canm:#x} out of code range)" if canm else
                          f"opcode_canm1_canm2          = FAILED: {err}")
                    failures.append("opcode_canm1_canm2 invalid")
                else:
                    print(f"opcode_canm1_canm2          = {canm:#010x}")
                    fedp, err = get_absolute_value(exe_data, canm, 0xC1)
                    print(f"field_event_data_ptr        = "
                          f"{fedp:#010x}" if fedp is not None else
                          f"field_event_data_ptr        = FAILED: {err}")
                    if fedp != EXPECT_FIELD_EVENT_DATA_PTR:
                        failures.append(
                            f"field_event_data_ptr {fedp:#x} != expected "
                            f"{EXPECT_FIELD_EVENT_DATA_PTR:#x}")
                    else:
                        print(f"  MATCHES FFNx ff7.h comment "
                              f"({EXPECT_FIELD_EVENT_DATA_PTR:#x})")

        # --- field_update_models_positions chain ------------------------
        fump, err = get_relative_call(exe_data, FIELD_LOOP_63C17F, 0x5DD)
        if fump is None:
            print(f"field_update_models_positions = FAILED: {err}")
            failures.append(f"field_update_models_positions: {err}")
        else:
            print(f"field_update_models_positions = {fump:#010x}")

            pmid, err = get_absolute_value(exe_data, fump, 0x45D)
            print(f"field_player_model_id       = "
                  f"{pmid:#010x}" if pmid is not None else
                  f"field_player_model_id       = FAILED: {err}")
            # No FFNx comment gives an expected value; sanity: must be a
            # data/BSS address in the same general region as other globals.
            if pmid is None or not (0xC00000 <= pmid <= 0xDF0000):
                failures.append(
                    f"field_player_model_id {pmid} outside expected "
                    f"data region 0xC00000-0xDF0000")

            nmod, err = get_absolute_value(exe_data, fump, 0x25)
            print(f"field_n_models              = "
                  f"{nmod:#010x}" if nmod is not None else
                  f"field_n_models              = FAILED: {err}")
            if nmod is None or not (0xC00000 <= nmod <= 0xDF0000):
                failures.append(
                    f"field_n_models {nmod} outside expected data region")

        print()
        print("=" * 70)
        if failures:
            print("RESULT: FAILED — do not trust these addresses:")
            for f in failures:
                print(f"  - {f}")
            print(f"Log saved to: {log_path}")
            return 1
        print("RESULT: OK — all chains resolved and cross-checks passed.")
        print("Addresses for ff7_addresses.h:")
        print(f"  MODULES_GLOBAL_OBJECT   = {mgo:#010x}  (key input at +0x68)")
        print(f"  FIELD_EVENT_DATA_PTR    = {fedp:#010x}  (stride 0x88, pos at +0x0C)")
        print(f"  FIELD_PLAYER_MODEL_ID   = {pmid:#010x}  (u16)")
        print(f"  FIELD_N_MODELS          = {nmod:#010x}  (u16)")
        print(f"Log saved to: {log_path}")
        return 0
    finally:
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    sys.exit(main())
