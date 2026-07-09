#!/usr/bin/env python3
"""
ff7_ffnx_pointer_scan.py -- Find FFNx's own resolved `battle_menu_state` /
`issued_command_id` pointers by scanning FFNx's loaded module memory,
2026-07-06.

Background:
  FFNx's ff7_data.h resolves these via a long chain of get_relative_call /
  get_absolute_value derivations anchored at the game's boot-time
  game_obj->engine_loop_obj.main_loop pointer:

    battle_main_loop          = get_absolute_value(main_loop, 0x89A)
    battle_menu_update_6CE8B3 = get_relative_call(battle_main_loop, 0x368)
    battle_sub_6DB0EE         = get_relative_call(battle_menu_update_6CE8B3, 0xD9)
    battle_menu_state_fn_table= get_absolute_value(battle_sub_6DB0EE, 0x1B4)  [64 entries]
    handle_actor_ready        = battle_menu_state_fn_table[0]
    battle_menu_state (WORD*) = get_absolute_value(handle_actor_ready, 0x17B)
    dispatch_chosen_battle_action = get_relative_call(battle_sub_6DB0EE, 0x50E)
    issued_command_id (byte*)     = get_absolute_value(dispatch_chosen_battle_action, 0x12B)

  Reconstructing this chain ourselves requires the game's boot-time
  game_obj pointer, which isn't a fixed address (FFNx obtains it via a
  parameter passed to its own driver-init hook).

  SHORTCUT: FFNx (module name "AF3DN.P", confirmed present via
  GetModuleHandleA in our own Resolve()) already computed these pointers
  once at startup and holds them as static globals inside its own loaded
  module. `battle_menu_state` and `issued_command_id` are POINTERS INTO
  THE GAME's memory (not into FFNx's own module), so their pointed-to
  VALUES change as the game runs, but the pointer VALUES THEMSELVES,
  once resolved, stay constant for the rest of the process lifetime.

  This script:
    1. Finds AF3DN.P's module base/size in the running ff7_en.exe process.
    2. Scans that module's memory for DWORD-aligned values that look like
       pointers into the known battle/UI-state region (0x00BE0000-0x00E00000
       -- where G_BATTLE_MODEL_STATE, G_ACTIVE_ACTOR_ID, MENU_CURSOR,
       CONFIG_ROW, KERNEL2_REQUEST_BASE etc. all already live).
    3. Reports each candidate: (address inside AF3DN.P) -> (pointed-to
       game address), plus the CURRENT WORD value at that pointed-to
       address (so obviously-wrong ranges can be eyeballed out).

  Run ff7_battle_menu_pointer_verify.py afterward to live-monitor the
  most plausible candidates while pressing Up/Down.

USAGE:
  Get into a battle with the command window open, then run this script.
"""
import ctypes
import struct
import subprocess
import sys
import os
import time

PROCESS_NAME = "ff7_en.exe"
FFNX_MODULE_NAME = "AF3DN.P"

# Broadened after the narrow 0xBE0000-0xE00000 battle-state window turned out
# to be all periodic animation noise, not the real cursor (2026-07-06). Cast
# a much wider net across the full static+near-heap range.
TARGET_LO = 0x00400000
TARGET_HI = 0x02000000

# Only print candidates whose CURRENT value looks like a plausible small
# command index. Full unfiltered list still goes to the log file via Tee.
PRINT_MAX_VALUE = 10

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

k32 = ctypes.windll.kernel32


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("th32ModuleID", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("GlblcntUsage", ctypes.c_ulong),
        ("ProccntUsage", ctypes.c_ulong),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", ctypes.c_ulong),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]


def find_pid(exe_name):
    out = subprocess.check_output(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV', '/NH'],
        text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == exe_name.lower():
            return int(parts[1])
    return None


def find_module(pid, module_name):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value:
        return None
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    result = None
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            name = me.szModule.decode('ascii', errors='ignore')
            if name.lower() == module_name.lower():
                result = (ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0,
                          me.modBaseSize)
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return result


def list_modules(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value:
        return []
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    names = []
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            names.append(me.szModule.decode('ascii', errors='ignore'))
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return names


def read_region(handle, lo, size):
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(lo), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytes(buf.raw)
    if read.value > 0:
        return bytes(buf.raw[:read.value])
    return None


def read_u16(handle, addr):
    buf = ctypes.create_string_buffer(2)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, 2, ctypes.byref(read))
    return struct.unpack_from('<H', buf.raw)[0] if ok and read.value == 2 else None


def read_u8(handle, addr):
    buf = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, 1, ctypes.byref(read))
    return buf.raw[0] if ok and read.value == 1 else None


IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000


def writable_data_ranges(module_data):
    """
    Parse the PE header of an in-memory module image and return a list of
    (offset, size, name) for sections that are writable and NOT executable
    -- i.e. .data/.bss, not .text. Real global pointers live here; .text is
    full of coincidental rel32/imm32 values that alias into any address range.
    """
    pe_off = struct.unpack_from('<I', module_data, 0x3C)[0]
    nsec = struct.unpack_from('<H', module_data, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', module_data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_hdr_size
    ranges = []
    for i in range(nsec):
        s = sec_off + i * 40
        name = module_data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', module_data, s + 8)[0]
        vaddr = struct.unpack_from('<I', module_data, s + 12)[0]
        characteristics = struct.unpack_from('<I', module_data, s + 36)[0]
        is_writable = bool(characteristics & IMAGE_SCN_MEM_WRITE)
        is_exec = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
        if is_writable and not is_exec:
            ranges.append((vaddr, vsize, name))
    return ranges


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, f"ffnx_pointer_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout

    class Tee:
        def write(self, s):
            real_stdout.write(s); log_file.write(s); log_file.flush()
        def flush(self):
            real_stdout.flush(); log_file.flush()
    sys.stdout = Tee()

    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if not pid:
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        mod = find_module(pid, FFNX_MODULE_NAME)
        if not mod:
            print(f"ERROR: module '{FFNX_MODULE_NAME}' not found. Loaded modules:")
            for n in list_modules(pid):
                print(f"  {n}")
            return
        mod_base, mod_size = mod
        print(f"{FFNX_MODULE_NAME}: base=0x{mod_base:08X} size=0x{mod_size:X} ({mod_size//1024} KB)")

        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            print("ERROR: OpenProcess failed.")
            return

        data = read_region(handle, mod_base, mod_size)
        if data is None:
            print("ERROR: could not read module memory.")
            return
        print(f"Read {len(data)} bytes from {FFNX_MODULE_NAME}.\n")

        ranges = writable_data_ranges(data)
        print(f"Writable non-executable sections in {FFNX_MODULE_NAME}:")
        for vaddr, vsize, name in ranges:
            print(f"  {name:8s}  RVA=0x{vaddr:06X}  size=0x{vsize:X} ({vsize//1024} KB)")
        print()

        print(f"Scanning writable data for DWORD pointers into "
              f"0x{TARGET_LO:08X}-0x{TARGET_HI:08X} ...")
        candidates = []
        for vaddr, vsize, name in ranges:
            lo = vaddr
            hi = min(vaddr + vsize, len(data))
            for i in range(lo, hi - 3, 4):   # 4-byte aligned
                val = struct.unpack_from('<I', data, i)[0]
                if TARGET_LO <= val < TARGET_HI:
                    candidates.append((mod_base + i, val))

        print(f"Found {len(candidates)} aligned candidates total "
              f"(printing only those with u8 <= {PRINT_MAX_VALUE}; "
              f"full list is in the log file).\n")
        print(f"{'AF3DN.P addr':14}  {'-> points to':12}  {'u16 now':>8}  {'u8 now':>7}")
        print(f"{'-'*14}  {'-'*12}  {'-'*8}  {'-'*7}")
        shown = 0
        all_lines = []
        for static_addr, target in sorted(candidates, key=lambda t: t[1]):
            u16v = read_u16(handle, target)
            u8v = read_u8(handle, target)
            u16s = f"{u16v}" if u16v is not None else "?"
            u8s = f"{u8v}" if u8v is not None else "?"
            line = f"0x{static_addr:08X}      0x{target:08X}    {u16s:>8}  {u8s:>7}"
            all_lines.append((u8v, target, line))
            if u8v is not None and u8v <= PRINT_MAX_VALUE:
                print(line)
                shown += 1
        print(f"\n({shown} shown of {len(candidates)} total)")

        # Full list always written to the log file (not the console) for reference.
        _log_only = log_file
        _log_only.write("\n\nFULL UNFILTERED LIST (all candidates, any value):\n")
        for u8v, target, line in sorted(all_lines, key=lambda t: (t[0] is None, t[0])):
            _log_only.write(line + "\n")
        _log_only.flush()

        print(f"\nLog saved to: {log_path}")
        print("\nNEXT STEP: pick candidates whose u16/u8 'now' value looks like a small")
        print("plausible command index (0-6), then live-monitor them while pressing")
        print("Up/Down with ff7_battle_menu_pointer_verify.py (pass their target addrs).")

        k32.CloseHandle(handle)
    finally:
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
