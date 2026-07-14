#!/usr/bin/env python3
"""
ff7_field_models_dump.py -- One-shot dump of the LIVE field file buffer's
section table and MODEL LOADER section, to pin down (a) which section index
holds the model loader on PC and (b) its exact per-model entry format
(2026-07-13, save-point category investigation).

WHY:
  The pathfinder's People category names everyone "Person N". Field-file
  section 3 (per the qhimm PSX-derived section order: script, camera, MODEL
  LOADER, palette, walkmesh, tilemap, encounter, triggers, background) lists
  every model's file name in LOAD ORDER -- the same order as the
  field_event_data array the mod walks. Matching a model's name identifies
  the save point (its own category) and later can name NPCs.

  BUT the June live dump of bombers_start (research doc section 5) showed
  section index 2 as a ~6-byte "(empty/padding)" section -- either that
  field's model section really is elsewhere or the June content labels were
  guesses. HRC names are plain ASCII inside the buffer, so ONE dump of a
  loaded field settles both questions by inspection.

WHAT:
  Reads (no writes) from the running ff7_en.exe:
    - buf = u32[0xCFF594]                     (FIELD_FILE_BUFFER)
    - section offsets = 9 u32s at buf+6       (each -> 4-byte size prefix)
    - field name + n_models/player id for context
  For every section: offset, size-prefix, and all printable-ASCII runs of
  4+ chars in the first 4KB (model/HRC/animation names pop out immediately).
  For the section(s) containing ".HRC": a hex dump of the first 0x200 bytes
  AND a u16-length-prefixed-string walk attempt, printing field offsets so
  the per-model record layout can be reconstructed from the log.

RUN: game running, any field loaded (standing anywhere is fine). One shot.
"""

import ctypes
import subprocess
import sys
import time
import os
import string
import struct

PROCESS_NAME = "ff7_en.exe"
FIELD_FILE_BUFFER = 0x00CFF594
FIELD_N_MODELS    = 0x00CFF73E
FIELD_PLAYER_ID   = 0x00CC162C
TRIGGERS_HDR_PTR  = 0x00CFF454
PROCESS_VM_READ   = 0x0410


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log = log_file
    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
    def flush(self):
        self._terminal.flush()
        self._log.flush()
    def __getattr__(self, name):
        return getattr(self._terminal, name)


def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if exe_name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def read_mem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return buf.raw
    return None


def ascii_runs(data, min_len=4):
    """Yield (offset, string) for printable ASCII runs."""
    printable = set(string.ascii_letters + string.digits + '._- ')
    run = []
    start = 0
    for i, b in enumerate(data):
        c = chr(b)
        if c in printable:
            if not run:
                start = i
            run.append(c)
        else:
            if len(run) >= min_len:
                yield start, ''.join(run)
            run = []
    if len(run) >= min_len:
        yield start, ''.join(run)


def hexdump(data, base_off, limit):
    lines = []
    for row in range(0, min(len(data), limit), 16):
        chunk = data[row:row+16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        text = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk)
        lines.append(f'  +{base_off+row:05X}: {hexs:<47} {text}')
    return '\n'.join(lines)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir, f"field_models_dump_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    sys.stdout = Tee(sys.__stdout__, log_file)
    print(f"Output saving to: {log_path}\n")

    pid = find_pid(PROCESS_NAME)
    if pid is None:
        print("ERROR: ff7_en.exe not running. Launch the game and load a field first.")
        return
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ, False, pid)
    if not handle:
        print("ERROR: OpenProcess failed.")
        return
    try:
        raw = read_mem(handle, FIELD_FILE_BUFFER, 4)
        buf = struct.unpack('<I', raw)[0] if raw else 0
        print(f"field buffer = 0x{buf:08X}")
        if buf < 0x10000:
            print("ERROR: no field loaded (buffer pointer null). Stand on a field and rerun.")
            return

        # Context: field name, model counts.
        hdrp = struct.unpack('<I', read_mem(handle, TRIGGERS_HDR_PTR, 4))[0]
        fname = read_mem(handle, hdrp, 9) if hdrp > 0x10000 else b''
        fname = (fname or b'').split(b'\0')[0].decode('ascii', 'replace')
        nmod = struct.unpack('<H', read_mem(handle, FIELD_N_MODELS, 2))[0]
        pmid = struct.unpack('<H', read_mem(handle, FIELD_PLAYER_ID, 2))[0]
        print(f"field name = '{fname}'   n_models = {nmod}   player model id = {pmid}\n")

        offs = struct.unpack('<9I', read_mem(handle, buf + 6, 36))
        print("section table (buf+6):")
        for i, off in enumerate(offs):
            size_raw = read_mem(handle, buf + off, 4)
            size = struct.unpack('<I', size_raw)[0] if size_raw else -1
            print(f"  section {i}: buf+0x{off:06X}  size_prefix={size}")
        print()

        hrc_sections = []
        for i, off in enumerate(offs):
            size = struct.unpack('<I', read_mem(handle, buf + off, 4))[0]
            take = min(max(size, 0), 4096)
            data = read_mem(handle, buf + off + 4, take) if take > 0 else None
            if not data:
                print(f"-- section {i}: unreadable/empty --")
                continue
            strs = list(ascii_runs(data))
            print(f"-- section {i} (size {size}): {len(strs)} ASCII runs in first {take} bytes --")
            for so, s in strs[:40]:
                print(f"   +0x{so:04X}: '{s}'")
            if any('.HRC' in s.upper() for _, s in strs):
                hrc_sections.append(i)
            print()

        for i in hrc_sections:
            off = offs[i]
            size = struct.unpack('<I', read_mem(handle, buf + off, 4))[0]
            take = min(size, 0x600)
            data = read_mem(handle, buf + off + 4, take)
            print(f"== HEX DUMP: section {i} (holds .HRC names), first 0x{take:X} bytes ==")
            print(hexdump(data, 0, take))
            print()
            # u16-length-prefixed string walk from +2 skipping a u16 header
            # pair guess: print every position where u16 <= 32 is followed by
            # that many printable chars (candidate length-prefixed strings).
            print(f"== length-prefixed string candidates in section {i} ==")
            for p in range(0, min(len(data) - 2, 0x580)):
                ln = struct.unpack_from('<H', data, p)[0]
                if 2 <= ln <= 32 and p + 2 + ln <= len(data):
                    chunk = data[p+2:p+2+ln]
                    if all(0x20 <= b <= 0x7E for b in chunk):
                        print(f"   +0x{p:04X}: len={ln} '{chunk.decode('ascii')}'")
            print()

        if not hrc_sections:
            print("NOTE: no '.HRC' strings found in any section's first 4KB —")
            print("model names may use another extension or live deeper; see the")
            print("ASCII runs above for what IS there.")

        print(f"\nLog saved to: {log_path}")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


if __name__ == '__main__':
    main()
