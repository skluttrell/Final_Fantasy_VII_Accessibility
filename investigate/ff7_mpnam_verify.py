#!/usr/bin/env python3
"""
ff7_mpnam_verify.py -- LIVE verify of the MPNAM location-name buffer found
statically the same day (2026-07-16, ff7_mpnam_static.py):

  0xDC0C44 (= savemap+0xF0C): FF7-encoded friendly location name, <= 0x17
  bytes, written by the MPNAM opcode's storage callee 0x633691 with dialog
  tokens decoded (char-name tokens resolved via 0x6CB9B8).

This watcher decodes the buffer every 250ms for 90 seconds and reports
(+ speaks) its value and every change, alongside FIELD_ID, so one short
play window proves: (a) the buffer holds the CURRENT location's friendly
name, (b) whether it updates on screen changes (MPNAM is a script opcode,
so areas sharing a name may not rewrite it every screen — that behavior
is exactly what the mod needs to know before speaking it).

Speech: PowerShell System.Speech subprocess — the pywin32 SAPI path
silently degraded to console-only in today's earlier scan (this box's
python has no win32com), which left the blind player with a mute script.
PowerShell needs nothing installed.
"""
import sys, os, struct, ctypes, datetime, time, subprocess

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"mpnam_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore_stdout():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore_stdout)
print(f"Output saving to: {_log_path}\n")

def say(text):
    """Fire-and-forget PowerShell SAPI — no python packages needed."""
    print(f"[SAY] {text}")
    try:
        safe = text.replace("'", "''")
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command",
             f"Add-Type -AssemblyName System.Speech; "
             f"(New-Object System.Speech.Synthesis.SpeechSynthesizer)."
             f"Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"  (speech failed: {e})")

# -- attach ----------------------------------------------------------------------
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

def find_pid(name='ff7_en.exe'):
    out = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {name}',
                                   '/FO', 'CSV', '/NH'], text=True)
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == name:
            return int(parts[1])
    raise RuntimeError(f"{name} not running")

pid = find_pid()
h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    raise ctypes.WinError(ctypes.get_last_error())
print(f"Attached to ff7_en.exe pid={pid} (read-only)\n")

def rpm(addr, size):
    buf = (ctypes.c_ubyte * size)()
    n = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                 ctypes.byref(n)) or n.value != size:
        return None
    return bytes(buf)

def r_i16(a):
    b = rpm(a, 2);  return struct.unpack('<h', b)[0] if b else None

# -- addresses --------------------------------------------------------------------
LOCATION_NAME = 0xDC0C44   # savemap+0xF0C; MPNAM callee writes <= 0x17 bytes
NAME_LEN      = 0x20       # read a little past the cap to see terminators
FIELD_ID      = 0xCC15D0

def decode(buf):
    out = []
    for b in buf:
        if b == 0xFF:
            break
        out.append(chr(b + 0x20) if 0x00 <= b <= 0x5E else '?')
    return ''.join(out).strip()

say("Location name verify running for ninety seconds. "
    "Walk across a screen or two.")

deadline = time.time() + 90
last_txt = None
last_fid = None
while time.time() < deadline:
    buf = rpm(LOCATION_NAME, NAME_LEN)
    fid = r_i16(FIELD_ID)
    now = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
    if fid != last_fid:
        print(f"[{now}] FIELD_ID {last_fid} -> {fid}")
        last_fid = fid
    if buf is not None:
        txt = decode(buf)
        if txt != last_txt:
            hx = ' '.join(f"{b:02X}" for b in buf)
            print(f"[{now}] 0xDC0C44 = '{txt}'")
            print(f"  raw: {hx}")
            say(f"Location name reads: {txt}" if txt
                else "Location buffer is empty.")
            last_txt = txt
    time.sleep(0.25)

print("\n=== SUMMARY ===")
print(f"final value: '{last_txt}'")
say("Verify finished.")
