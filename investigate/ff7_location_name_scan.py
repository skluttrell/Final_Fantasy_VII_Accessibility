#!/usr/bin/env python3
"""
ff7_location_name_scan.py -- Live discovery of the FRIENDLY location name
("Sector 1 Station") in memory (2026-07-16; plan from TODO.txt "[NAV]
Friendly map names").

GOAL:
  The v2.23 screen-change announcement and the M key speak the INTERNAL
  field name ("nmkin 2"). The game itself displays a friendly location
  string at the bottom of the MAIN MENU -- so a live copy must exist in
  memory during play. Community savemap docs place a 32-byte location
  string in the save-slot PREVIEW block (before the character records),
  and our savemap base is confirmed (0xDBFD38; char records at +0x54,
  v2.19) -- so the preview block is savemap+0x04..+0x53. The unknown is
  whether that copy is maintained LIVE during play (the field MPNAM
  opcode suggests yes) or only written at save time.

METHOD (empirical -- no offset assumptions inside the window):
  Watch savemap+0x00..+0x54 at 250ms. Decode EVERY FF7-text run (>= 4
  printable chars) in the window and report each with its exact offset.
  Also stamp FIELD_ID (screen changes) and MENU_OPEN transitions, so the
  log shows WHEN the string updates:
    - text present at start and changing on screen change  -> live copy,
      mod can read it directly (best case);
    - text refreshing only when the menu opens             -> menu-open
      writer; mod can still read it, staleness noted;
    - no text ever                                         -> not in the
      preview block; plan a delta scan next session.

  All findings are SPOKEN via SAPI (standing rule: the blind player never
  needs the console mid-test). Test choreography, spoken by the script:
    1. Start on any field screen. The script reads the window and speaks
       any text it finds.
    2. Walk through an exit to ANOTHER screen (a "Screen:" announcement
       from the mod marks it). The script reports changes.
    3. Open the MAIN MENU briefly, close it.
    4. Cross one more screen boundary, then press Ctrl+C in the console
       (or just leave it running and tell Claude to read the log).
"""
import sys, os, struct, ctypes, datetime, time

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"location_name_scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# Speech via PowerShell System.Speech — NEVER pywin32 (this script's first
# run was silently MUTE for the blind player because the system python has
# no win32com; see feedback_investigation_scripts memory, 2026-07-16).
import subprocess as _sp
def say(text):
    print(f"[SAY] {text}")
    try:
        safe = text.replace("'", "''")
        _sp.Popen(["powershell", "-NoProfile", "-Command",
                   f"Add-Type -AssemblyName System.Speech; "
                   f"(New-Object System.Speech.Synthesis.SpeechSynthesizer)."
                   f"Speak('{safe}')"],
                  stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    except Exception as e:
        print(f"  (speech failed: {e})")

# -- attach ----------------------------------------------------------------------
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

def find_pid(name='ff7_en.exe'):
    import subprocess
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
def r_u8(a):
    b = rpm(a, 1);  return b[0] if b else None

# -- addresses --------------------------------------------------------------------
SAVEMAP    = 0xDBFD38     # confirmed base (char records at +0x54, v2.19)
WIN_LEN    = 0x54         # preview block: +0x00..+0x53
FIELD_ID   = 0xCC15D0
MENU_OPEN  = 0xDC12DC
GAME_MODE  = 0xCC0D89

# -- FF7 text decode (display chars only; 0xFF = terminator) ----------------------
def ff7_char(b):
    # Standard PC table: byte 0x00 = ' ', ascending ASCII (char - 0x20).
    if 0x00 <= b <= 0x5E:
        return chr(b + 0x20)
    return None

def text_runs(window):
    """Every decodable run of >= 4 chars: list of (offset, text)."""
    runs = []
    i = 0
    while i < len(window):
        chars = []
        start = i
        while i < len(window):
            c = ff7_char(window[i])
            if c is None:
                break
            chars.append(c)
            i += 1
        run = ''.join(chars).strip()
        # >= 4 real chars filters the single-byte stat noise that happens
        # to fall in the printable range.
        if len(run) >= 4:
            runs.append((start, run))
        i = max(i, start) + 1
    return runs

def hexdump(window):
    out = []
    for off in range(0, len(window), 16):
        row = window[off:off + 16]
        hx = ' '.join(f"{b:02X}" for b in row)
        out.append(f"  +{off:04X}: {hx}")
    return '\n'.join(out)

# -- main watch loop ---------------------------------------------------------------
say("Location name scan running for three minutes. Stand on a field "
    "screen. I will read what I find, then: walk to another screen, "
    "open and close the main menu, and cross one more screen.")

last_window = None
last_field  = None
last_menu   = None
spoken_runs = set()

# Fixed three-minute window so the scan can run unattended in the
# background (Claude launches it and reads the log afterwards); Ctrl+C
# still ends it early when run by hand.
deadline = time.time() + 180

try:
    while time.time() < deadline:
        window = rpm(SAVEMAP, WIN_LEN)
        fid    = r_i16(FIELD_ID)
        menu   = r_u8(MENU_OPEN)
        now    = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

        if fid != last_field:
            print(f"[{now}] FIELD_ID {last_field} -> {fid}")
            last_field = fid
        if menu != last_menu:
            print(f"[{now}] MENU_OPEN {last_menu} -> {menu}")
            last_menu = menu

        if window is not None and window != last_window:
            changed = ([i for i in range(WIN_LEN)
                        if last_window is not None and
                        window[i] != last_window[i]]
                       if last_window is not None else [])
            print(f"[{now}] savemap preview window "
                  f"{'INITIAL' if last_window is None else f'CHANGED at offsets {changed}'}")
            print(hexdump(window))
            runs = text_runs(window)
            if runs:
                for off, txt in runs:
                    print(f"  TEXT at savemap+0x{off:02X}: '{txt}'")
                    key = (off, txt)
                    if key not in spoken_runs:
                        spoken_runs.add(key)
                        say(f"Text at offset {off:#x}: {txt}")
            else:
                print("  (no decodable text runs)")
                if last_window is None:
                    say("No text found in the preview block yet. "
                        "Try opening the main menu.")
            last_window = window

        time.sleep(0.25)
except KeyboardInterrupt:
    pass

print("\n=== SUMMARY ===")
if spoken_runs:
    print("Distinct text runs observed (offset, text):")
    for off, txt in sorted(spoken_runs):
        print(f"  savemap+0x{off:02X}: '{txt}'")
    say("Scan finished. Findings are in the log. You can keep playing.")
else:
    print("NO text runs observed in savemap+0x00..0x53 at any point.")
    print("The live location string is NOT in the preview block -> next")
    print("step is a delta scan across a screen change (menu module .data).")
    say("Scan stopped. No text found. We will need a wider scan.")
