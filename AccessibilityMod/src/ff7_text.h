/*
 * ff7_text.h -- Decode FF7's custom text encoding to wide strings for TTS.
 *
 * FF7 stores all in-game text (dialog, item names, spell names, etc.) in a
 * proprietary 8-bit encoding. It is NOT ASCII or any standard codepage.
 *
 * Encoding rules (from FFNx/src/voice.cpp decode_ff7_text()):
 *
 *   0x00–0xDF  Normal printable character: actual char = encoded_byte + 0x20
 *              So encoded 0x41 ('A'-0x20=0x41) → ' ' (space),
 *                 encoded 0x61 → 'a', encoded 0x61+0x20 → 'a' is actually...
 *              Wait: space is 0x20, encoded 0x00 → 0x00+0x20=0x20=' '.
 *              'A' is 0x41 ASCII, so encoded 'A'-0x20 = 0x21 → 'A'.
 *
 *   0xE0        Newline — replaced with a space in TTS output so the screen
 *               reader reads through line breaks naturally.
 *
 *   0xEA        Character name token: Cloud
 *   0xEB        Character name token: Barret
 *   0xEC        Character name token: Tifa
 *   0xED        Character name token: Aerith (Aeris)
 *   0xEE        Character name token: Red XIII
 *   0xEF        Character name token: Yuffie
 *   0xF0        Character name token: Cait Sith
 *   0xF1        Character name token: Vincent
 *   0xF2        Character name token: Cid
 *               These tokens are replaced with the character's in-game name.
 *               In v1 we use the default English names. Future: read from savemap.
 *
 *   0xEB–0xEF followed by three more bytes (4-byte sequence total):
 *               Dynamic token (item_name, number, target_name, attack_name, etc.)
 *               In v1 we replace these with placeholder descriptions. The game
 *               resolves them at render time from script memory banks that are
 *               not trivially accessible from our hook context.
 *               NOTE: 0xEB, 0xEC, 0xED, 0xEE, 0xEF also serve as character name
 *               tokens. The context determines which use applies. In practice,
 *               character name tokens appear only at the START of dialog strings
 *               (the character speaking indicator), while dynamic tokens appear
 *               mid-string. We distinguish them by position (index == 0).
 *
 *   0xF8        Skip token: the following 2 bytes are formatting data and should
 *               be consumed without output. Total: 3 bytes (0xF8 + 2 data bytes).
 *
 *   0xFF        End of string. Decoding stops here.
 *
 * All output is UTF-16 (std::wstring) for direct use with Tolk's wchar_t* API.
 */

#pragma once
#include <string>

namespace FF7Text {

/*
 * Decode: Convert a FF7-encoded string to a wide UTF-16 string suitable for
 * passing to Tolk_Speak().
 *
 * encoded_text: Pointer to the FF7-encoded string in game memory.
 *               May be nullptr (returns empty string).
 * Returns an empty wstring if the input is null or empty.
 *
 * This function does NOT modify game memory. It reads sequentially from
 * encoded_text until a 0xFF terminator is encountered.
 */
std::wstring Decode(const char* encoded_text);

/*
 * DecodeChar: Decode ONE FF7-encoded byte to its speakable wchar_t, or L'\0'
 * if the byte has no printable/speakable glyph (terminator, control bytes,
 * token bytes, discarded symbols).
 *
 * WHY THIS EXISTS: fixed-size name/label buffers (e.g. the name-entry screen's
 * NAME_ENTRY_BUFFER) need per-byte decoding with a caller-controlled length
 * cap and no whitespace trimming — Decode() above is dialog-oriented (token
 * expansion, trailing-space trim) and unsuitable there. This helper shares
 * the same kExtendedChars table and canonical_ch() filter, so encoding fixes
 * land in one place: the naive byte+0x20 formula is only correct for bytes
 * 0x00-0x5E; extended bytes (e.g. 0xB5 = FF7's apostrophe) need the table.
 */
wchar_t DecodeChar(unsigned char byte);

} // namespace FF7Text
