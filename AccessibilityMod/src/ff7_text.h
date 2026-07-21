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
#include <vector>

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
 * encoded_text until a 0xFF terminator is encountered. Page breaks
 * (0xE8/0xE9) are flattened to a space, same as a newline -- use
 * DecodeMessagePages() below when the caller needs to pace speech to the
 * screen.
 */
std::wstring Decode(const char* encoded_text);

/*
 * DecodeLines: Same decoding as Decode(), but split into one string per
 * LINE -- every newline (0xE0/0xE7) or page break (0xE8/0xE9) starts a new
 * entry, instead of DecodeMessagePages()'s multi-line-per-page grouping.
 *
 * WHY A SEPARATE FUNCTION FROM DecodeMessagePages() (v2.30.4): the two
 * callers want different granularities. ASK choice menus (hook_ask) are
 * the opposite of flowing prose: each answer is conventionally its own
 * single screen line, so a newline IS the option boundary the cursor
 * moves between. DecodeLines() is for that case -- pairing decoded
 * line[i] with the choice cursor's option index i.
 */
std::vector<std::wstring> DecodeLines(const char* encoded_text);

/*
 * DecodeMessagePages: Same decoding as Decode(), but split into one
 * string per displayed PAGE, for callers (hook_message) that need to pace
 * speech to the screen instead of reading the whole multi-page message at
 * once.
 *
 * WHY THIS EXISTS (v2.30.4, revised v2.30.7): FF7's dialog rawptr holds
 * the COMPLETE multi-page message from the moment the window opens --
 * there is no "page 2 doesn't exist yet" state to wait for. A caller that
 * decodes the whole rawptr and speaks it once at window-open therefore
 * reads every page before the player has advanced past page 1 (player
 * report 2026-07-20 -- sounds like repeating because the display is still
 * catching up to what was already spoken).
 *
 * v2.30.4's first attempt (DecodePages, since removed) split ONLY on
 * explicit page-break bytes (0xE8/0xE9). That covers author-placed hard
 * breaks, but FF7's dialog box also soft-wraps to a new screen purely
 * because it ran out of the ~4 lines it can show at once, with NO special
 * byte marking that point in the source text -- a dialog that relies on
 * that (player report 2026-07-20) decoded as a single page, so it all
 * spoke at once and every later on-screen page turn (confirmed still
 * happening by the STATE MACHINE's own PAGE transitions) found nothing
 * left to say: dead silence, no cue to press the button.
 *
 * This version groups decoded LINES (same splitting as DecodeLines) into
 * pages of up to 4, but an explicit page-break byte still forces an early
 * page close regardless of line count (some passages use deliberately
 * SHORT hard-broken pages for pacing, and merging those with what follows
 * would be wrong). The 4-line cap is an ASSUMPTION (FF7's documented
 * standard message-window capacity), not something read from the game.
 *
 * Returns an empty vector if the input is null. A page whose visible text
 * is empty after filtering still gets an (empty) entry, so indices stay
 * aligned with the game's own page-advance event count -- callers should
 * skip speaking empty entries rather than dropping them from the vector.
 */
std::vector<std::wstring> DecodeMessagePages(const char* encoded_text);

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

/*
 * Live character-name provider (v2.19).
 *
 * Dialog strings reference party characters by token (0xEA=Cloud .. 0xF2=Cid),
 * and the player can RENAME every one of them on the naming screen — so the
 * hardcoded default names are wrong the moment a player renames anyone.
 * The decoder itself must stay free of game-memory knowledge (it is a pure
 * byte-stream transform, unit-testable in isolation), so the savemap reader
 * lives in proxy.cpp and is injected here as a callback at init time.
 *
 * fn(char_id, out): char_id 0-8 (token byte - 0xEA); returns true and fills
 * `out` with a non-empty current name, or false to use the default English
 * name. The provider must be safe to call from any thread at any time
 * (proxy.cpp's reads static savemap memory, which always exists).
 */
typedef bool (*NameProviderFn)(int char_id, std::wstring& out);
void SetNameProvider(NameProviderFn fn);

/*
 * DefaultCharName: the default English name for character ID 0-8 (Cloud..Cid),
 * or nullptr if out of range. Exposed so proxy.cpp's battle labels can share
 * the ONE defaults table instead of keeping private copies (pre-v2.19 there
 * were three identical tables across two files).
 */
const wchar_t* DefaultCharName(int char_id);

} // namespace FF7Text
