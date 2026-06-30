#!/usr/bin/env python3
"""
ff7_investigate.py — Live memory investigation of FF7 dialog system.

Run this script WHILE FF7 is running to capture the true layout of the
script section header and the exact rawptr values for each dialog.

Usage:
    pip install frida frida-tools   (one-time setup)
    python ff7_investigate.py

This answers:
  - What are bytes 0-15 of script_data for each field?
    (Resolves the unknown1 vs wStringOffset layout debate in ff7.h)
  - What does DIALOG_TEXT_PTRS[w] point to for each dialog?
    (Ground truth rawptr values, including stale vs. correct timing)
  - Is buf_off=0x1955D really garbage, or valid for some dialog?

Output format:
  FIELD buf=0x... sd=0x... hdr=[XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX]
  [winN] ptr=0x... buf_off=0x... text='...'

  The "hdr" bytes correspond to ff7_field_script_header (from FFNx src/ff7.h):
    bytes 0-1: unknown1 (WORD)
    byte  2  : nEntities
    byte  3  : nModels
    bytes 4-5: wStringOffset (WORD) — if correct, should index dialog strings
    bytes 6-7: nAkaoOffsets (WORD)
    bytes 8-9: scale (WORD)
"""

import frida
import sys
import time

PROCESS_NAME = "ff7_en.exe"

# Fixed addresses for FF7 2013 Steam (same build as 1.02 US retail).
# From FFNx externals_102_us.h and our ff7_addresses.h.
FIELD_FILE_BUFFER = 0xCFF594   # uint32* → pointer to field file buffer
FIELD_SCRIPT_PTR  = 0xCBF5E8   # uint32* → pointer to script section start
DIALOG_TEXT_PTRS  = 0xCBF578   # uint32[8] — per-window raw text pointers

# The Frida-side JavaScript. Runs in the target process.
# rpc.exports.snapshot() reads all relevant memory and returns a plain object.
JS_CODE = r"""
'use strict';

function safeReadU32(addr) {
    try { return Memory.readU32(ptr(addr)); }
    catch(e) { return 0; }
}

function safeReadBytes(addr, n) {
    try { return Array.from(Memory.readByteArray(ptr(addr), n)); }
    catch(e) { return []; }
}

// Read up to maxLen FF7-encoded bytes from addr, stopping at 0xFF (terminator).
function readFF7String(addr, maxLen) {
    if (!addr) return [];
    maxLen = maxLen || 120;
    var result = [];
    try {
        for (var i = 0; i < maxLen; i++) {
            var b = Memory.readU8(ptr(addr + i));
            if (b === 0xFF) break;
            result.push(b);
        }
    } catch(e) { /* stopped at unreadable page */ }
    return result;
}

rpc.exports = {
    snapshot: function() {
        // 0xCFF594 is a single pointer that holds the field file buffer address.
        // Previous version double-dereferenced (safeReadU32(safeReadU32(0xCFF594))),
        // which read the first 4 padding bytes of the buffer (always 0) instead of
        // the buffer address itself.
        var fieldBuf = safeReadU32(0xCFF594);

        // FIELD_SCRIPT_PTR is a single pointer (not double): it holds the address
        // of the script section data directly. Source: ff7_data.h field_script_ptr.
        var scriptData = safeReadU32(0xCBF5E8);

        // First 32 bytes of the script section header (ff7_field_script_header).
        var scriptHeader = scriptData ? safeReadBytes(scriptData, 32) : [];

        // wStringOffset from header bytes 4-5 (little-endian WORD).
        var wStringOffset = 0;
        if (scriptHeader.length >= 6) {
            wStringOffset = scriptHeader[4] | (scriptHeader[5] << 8);
        }

        // First 128 bytes at sd+wStringOffset: the dialog offset table.
        // This is the data our section lookup reads to find dialog text.
        // Seeing these bytes tells us how many dialog entries the table has
        // and why some dialog IDs miss the lookup.
        var dialogTableBytes = [];
        if (scriptData && wStringOffset >= 6 && wStringOffset <= 60000) {
            dialogTableBytes = safeReadBytes(scriptData + wStringOffset, 128);
        }

        // Per-window dialog text pointers: DIALOG_TEXT_PTRS[0..7].
        var dlgPtrs = [];
        var dlgTexts = [];
        for (var w = 0; w < 8; w++) {
            var p = safeReadU32(0xCBF578 + w * 4);
            dlgPtrs.push(p);
            dlgTexts.push(p ? readFF7String(p, 120) : []);
        }

        return {
            fieldBuf:         fieldBuf,
            scriptData:       scriptData,
            scriptHeader:     scriptHeader,
            wStringOffset:    wStringOffset,
            dialogTableBytes: dialogTableBytes,
            dlgPtrs:          dlgPtrs,
            dlgTexts:         dlgTexts
        };
    }
};
"""

# ---------------------------------------------------------------------------
# FF7 text decoder (approximate — enough for identification).
# Full decode lives in ff7_text.cpp; this is Python-side for investigation.
# ---------------------------------------------------------------------------

# Printable ASCII range (FF7 uses a shifted encoding where 0x20 = space...).
# The exact mapping from ff7_text.cpp:
FF7_CHAR_TABLE = {
    0x00: ' ', 0x01: '!', 0x02: '"', 0x03: '#', 0x04: '$', 0x05: '%',
    0x06: '&', 0x07: "'", 0x08: '(', 0x09: ')', 0x0A: '*', 0x0B: '+',
    0x0C: ',', 0x0D: '-', 0x0E: '.', 0x0F: '/',
    0x10: '0', 0x11: '1', 0x12: '2', 0x13: '3', 0x14: '4', 0x15: '5',
    0x16: '6', 0x17: '7', 0x18: '8', 0x19: '9', 0x1A: ':', 0x1B: ';',
    0x1C: '<', 0x1D: '=', 0x1E: '>', 0x1F: '?',
    0x20: '@', 0x21: 'A', 0x22: 'B', 0x23: 'C', 0x24: 'D', 0x25: 'E',
    0x26: 'F', 0x27: 'G', 0x28: 'H', 0x29: 'I', 0x2A: 'J', 0x2B: 'K',
    0x2C: 'L', 0x2D: 'M', 0x2E: 'N', 0x2F: 'O',
    0x30: 'P', 0x31: 'Q', 0x32: 'R', 0x33: 'S', 0x34: 'T', 0x35: 'U',
    0x36: 'V', 0x37: 'W', 0x38: 'X', 0x39: 'Y', 0x3A: 'Z', 0x3B: '[',
    0x3C: '\\',0x3D: ']', 0x3E: '^', 0x3F: '_',
    0x40: '`', 0x41: 'a', 0x42: 'b', 0x43: 'c', 0x44: 'd', 0x45: 'e',
    0x46: 'f', 0x47: 'g', 0x48: 'h', 0x49: 'i', 0x4A: 'j', 0x4B: 'k',
    0x4C: 'l', 0x4D: 'm', 0x4E: 'n', 0x4F: 'o',
    0x50: 'p', 0x51: 'q', 0x52: 'r', 0x53: 's', 0x54: 't', 0x55: 'u',
    0x56: 'v', 0x57: 'w', 0x58: 'x', 0x59: 'y', 0x5A: 'z',
    0xE0: '\n',  # newline
    0xEA: '{Cloud}', 0xEB: '{Barret}', 0xEC: '{Tifa}',
    0xED: '{Aeris}', 0xEE: '{Red XIII}', 0xEF: '{Yuffie}',
    0xF0: '{Cait Sith}', 0xF1: '{Vincent}', 0xF2: '{Cid}',
}

def decode_ff7(data, max_chars=60):
    """Decode a list of FF7 byte values to a human-readable string."""
    out = ''
    i = 0
    while i < len(data) and len(out) < max_chars:
        b = data[i]
        if b == 0xFF:
            break
        elif b in FF7_CHAR_TABLE:
            out += FF7_CHAR_TABLE[b]
        elif 0xE0 <= b <= 0xE9:
            # Control codes: skip the next byte(s)
            out += f'[{b:02X}]'
            if b in (0xE2, 0xE3, 0xE4, 0xE5, 0xE6):
                i += 1  # skip one parameter byte
        else:
            out += f'[{b:02X}]'
        i += 1
    return out


def format_header(hdr):
    """Format first 16 bytes of script_data as annotated hex."""
    if not hdr:
        return "(no data)"
    hex16 = ' '.join(f'{b:02X}' for b in hdr[:16])
    # Interpret key fields if we have enough bytes
    annotations = []
    if len(hdr) >= 2:
        w0 = hdr[0] | (hdr[1] << 8)
        annotations.append(f"[0-1]=0x{w0:04X}(unknown1?)")
    if len(hdr) >= 3:
        annotations.append(f"[2]={hdr[2]}(nEntities?)")
    if len(hdr) >= 4:
        annotations.append(f"[3]={hdr[3]}(nModels?)")
    if len(hdr) >= 6:
        w4 = hdr[4] | (hdr[5] << 8)
        annotations.append(f"[4-5]=0x{w4:04X}(wStringOffset?)")
    return f"[{hex16}]  {', '.join(annotations)}"


def main():
    print(f"Attaching to {PROCESS_NAME}...")
    try:
        session = frida.attach(PROCESS_NAME)
    except frida.ProcessNotFoundError:
        print(f"ERROR: {PROCESS_NAME} not found. Start FF7 first.")
        sys.exit(1)

    script = session.create_script(JS_CODE)
    script.load()

    last = None
    print("Attached. Polling every 100ms. Press Ctrl+C to stop.\n")
    print("Legend: buf_off = pointer offset from start of field file buffer")
    print("        hdr = first 16 bytes of script_data (ff7_field_script_header)")
    print()

    try:
        while True:
            snap = script.exports.snapshot()

            # Detect field change (new field buffer address).
            if last is None or snap['scriptData'] != last['scriptData']:
                ts = time.strftime('%H:%M:%S')
                print(f"\n{'='*60}")
                print(f"[{ts}] FIELD CHANGE")
                print(f"  fieldBuf   = 0x{snap['fieldBuf']:08X}")
                print(f"  scriptData = 0x{snap['scriptData']:08X}")
                if snap['scriptData'] and snap['fieldBuf']:
                    sd_off = snap['scriptData'] - snap['fieldBuf']
                    print(f"  sd offset from fieldBuf = 0x{sd_off:X} ({sd_off})")
                print(f"  header = {format_header(snap['scriptHeader'])}")
                wso = snap.get('wStringOffset', 0)
                if wso >= 6:
                    tbl = snap.get('dialogTableBytes', [])
                    hex_tbl = ' '.join(f'{b:02X}' for b in tbl[:64])
                    # Interpret first WORD as first_off → num_dialogs
                    if len(tbl) >= 2:
                        first_off = tbl[0] | (tbl[1] << 8)
                        num_dlg = first_off // 2
                        print(f"  wStringOffset=0x{wso:X}  first_off=0x{first_off:X} → num_dialogs={num_dlg}")
                    print(f"  dialog table (first 64 bytes at sd+wStringOffset):")
                    print(f"    {hex_tbl}")
                print()

            # Detect per-window pointer changes.
            for w in range(8):
                if last is None or snap['dlgPtrs'][w] != last['dlgPtrs'][w]:
                    ptr_val = snap['dlgPtrs'][w]
                    field_buf = snap['fieldBuf']
                    if ptr_val and field_buf and ptr_val >= field_buf:
                        buf_off = ptr_val - field_buf
                        off_str = f"buf_off=0x{buf_off:X}"
                    else:
                        buf_off = None
                        off_str = f"abs=0x{ptr_val:08X}"
                    text = decode_ff7(snap['dlgTexts'][w])
                    ts = time.strftime('%H:%M:%S')

                    # Annotate whether this rawptr passes the wStringOffset-anchored bounds.
                    # Mirrors is_valid_dialog_rawptr(): lower = sd+wStringOffset,
                    # upper = sd+wStringOffset+8192. Stale ptr sd+0x7A92 fails this
                    # even though it passed the old sd+32768 limit.
                    sd = snap['scriptData']
                    wso = snap.get('wStringOffset', 0)
                    if sd and ptr_val:
                        if wso >= 6 and wso <= 60000:
                            above_lower = ptr_val >= sd + wso
                            below_upper = ptr_val < sd + wso + 8192
                            if above_lower and below_upper:
                                bounds = "IN_BOUNDS"
                            elif not above_lower:
                                bounds = "REJECTED_below_wStringOffset"
                            else:
                                bounds = "REJECTED_above_upper_bound"
                        else:
                            bounds = "IN_BOUNDS" if ptr_val < sd + 32768 else "REJECTED_fallback32k"
                    else:
                        bounds = "?"

                    print(f"[{ts}] win={w} ptr=0x{ptr_val:08X} {off_str}  [{bounds}]")
                    print(f"         text='{text}'")

            last = snap
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n\nStopped by user.")
        print("\nSUMMARY: Look for patterns in the buf_off values for each window/dialog.")
        print("All buf_off values for the same field should be in a narrow range")
        print("(typically 0xA00 – 0xD00 for bombers_start). Values like 0x1955D or 0x9AC0")
        print("are stale pointers into non-dialog sections — the new upper bound rejects them.")
    finally:
        session.detach()


if __name__ == '__main__':
    main()
