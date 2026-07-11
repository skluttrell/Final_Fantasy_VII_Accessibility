#!/usr/bin/env python3
"""
ff7_kernel2_result_hunt.py -- Hunt for the REAL kernel2 lookup result pointer
during live battle flash messages (2026-07-11).

Background: ff7_kernel2_result_verify.py (same day) proved the request struct
0xDC38E8 (pending/section/idx) updates exactly at flash time (magic cast ->
sect=2 idx=30), but the documented result pointer 0xDC208C stays 0x00000000
through every battle action. The doc's store target is wrong or menu-only.
The consumer at 0x6D72E9 must put sub_41963C's returned text pointer
SOMEWHERE -- most likely a global near the other kernel2/menu-module globals.

Strategy: every 20ms, read two windows that bracket the known kernel2/menu
globals:
    A: 0xDC2000 - 0xDC2200   (around the documented-but-dead 0xDC208C)
    B: 0xDC3800 - 0xDC3A00   (around the request struct 0xDC38E8)
For every 4-aligned DWORD in each window that looks like a pointer into the
exe's data space, dereference it and FF7-decode 24 bytes. Report a candidate
address whenever ITS DEREFERENCED TEXT CHANGES between polls and decodes to
>= 3 printable chars. At flash time the real result slot will light up with
the action name; static pointers (never changing) stay silent after their
first report.

Correlate: each report line includes the current request sect/idx, so the
winner is the address whose text changes in the SAME poll window as sect/idx
and whose decode matches the on-screen flash text.

Run while in battle; press Ctrl+C to stop.
"""
import sys, os, struct, ctypes, datetime, subprocess, time

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_result_hunt_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b else None

def ff7_decode(data, max_bytes=24):
    out = []
    printable = 0
    for b in data[:max_bytes]:
        if b == 0xFF:
            break
        if b <= 0x5E:
            out.append(chr(b + 0x20))
            printable += 1
        else:
            out.append(f'[{b:02X}]')
    return ''.join(out), printable

# Windows to sweep: (start, end) inclusive-exclusive, 4-aligned.
WINDOWS = [
    (0x00DC2000, 0x00DC2200),   # around documented (dead) 0xDC208C
    (0x00DC3800, 0x00DC3A00),   # around live request struct 0xDC38E8
]

KERNEL2_REQUEST_SECTION = 0x00DC38EC
KERNEL2_REQUEST_IDX     = 0x00DC38F0

def ptr_plausible(p):
    # Data pointers in this 32-bit process: exe image / static data / heap.
    return 0x00400000 <= p < 0x7FFF0000

h = open_ff7()
print("Sweeping candidate windows every 20ms. Ctrl+C to stop.\n")
print(f"{'time':>12}  {'slot':>10}  {'ptr':>10}  {'sect':>4}  {'idx':>4}  decoded")

# last_text[slot_va] = last dereferenced text bytes seen through that slot.
last_text = {}

try:
    while True:
        sect = read_u32(h, KERNEL2_REQUEST_SECTION)
        idx  = read_u32(h, KERNEL2_REQUEST_IDX)
        for lo, hi in WINDOWS:
            blob = read_mem(h, lo, hi - lo)
            if blob is None:
                continue
            for off in range(0, len(blob) - 3, 4):
                p = struct.unpack_from('<I', blob, off)[0]
                if not ptr_plausible(p):
                    continue
                text = read_mem(h, p, 24)
                if text is None:
                    continue
                slot = lo + off
                if last_text.get(slot) == text:
                    continue
                first_sight = slot not in last_text
                last_text[slot] = text
                decoded, printable = ff7_decode(text)
                # Only report slots whose target text looks like words; on
                # first sight report regardless of change (baseline line).
                if printable < 3:
                    continue
                tag = 'NEW ' if first_sight else 'CHG '
                ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"{ts:>12}  {tag}0x{slot:06X}  0x{p:08X}  {sect:4d}  {idx:4d}  '{decoded}'")
        time.sleep(0.02)
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
