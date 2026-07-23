/*
 * ff7_text.cpp -- FF7 custom text encoding -> wstring for TTS output.
 * See ff7_text.h for the encoding specification overview.
 */

#include "ff7_text.h"
#include <cstdint>

namespace FF7Text {

namespace {

// v2.30.4: word-boundary guard shared by every content-insertion point in
// decode_walk() below. A byte that inserts substitute text (dynamic token,
// inline character name) or vanishes silently (unrecognized control byte)
// must not fuse the words on either side of it. The game's own renderer
// doesn't need an explicit space byte around these -- the icon/substitution
// (or simply the absence of a printed glyph) IS the separator on screen --
// but the flattened TTS string has nothing else to mark the gap.
//
// Player report 2026-07-20 (Wedge line): "Uhnothin'.sorry." (an unhandled
// control byte between "Uh" and "nothin'" vanished with no compensating
// space) and "Hey[item name]What about our money?" (the item-name token
// spliced directly into the surrounding words). Both are this same bug.
void guard_space(std::wstring& out)
{
    if (!out.empty() && out.back() != L' ') out += L' ';
}

} // namespace

// Default English character names, indexed as [byte - 0xEA].
// Token 0xEA=Cloud, 0xEB=Barret, ..., 0xF2=Cid.
// Used only when no name provider is registered or it has no live name yet
// (e.g. title screen before any save is loaded) — see char_name() below.
static const wchar_t* const kCharNames[] = {
    L"Cloud",      // 0xEA
    L"Barret",     // 0xEB
    L"Tifa",       // 0xEC
    L"Aerith",     // 0xED
    L"Red XIII",   // 0xEE
    L"Yuffie",     // 0xEF
    L"Cait Sith",  // 0xF0
    L"Vincent",    // 0xF1
    L"Cid",        // 0xF2
};
static constexpr int kCharNameCount = sizeof(kCharNames) / sizeof(kCharNames[0]);

// Live-name provider registered by proxy.cpp at init (v2.19). Kept as a
// plain function pointer (no std::function) so registration is atomic on
// x86 and needs no synchronization with the decode paths that read it.
static NameProviderFn g_name_provider = nullptr;

void SetNameProvider(NameProviderFn fn)
{
    g_name_provider = fn;
}

const wchar_t* DefaultCharName(int char_id)
{
    return (char_id >= 0 && char_id < kCharNameCount) ? kCharNames[char_id]
                                                      : nullptr;
}

// Resolve a character-name token index (0=Cloud .. 8=Cid) to the name the
// GAME would render right now: the live savemap name when the provider has
// one (players can rename every character on the naming screen), else the
// default English name. Empty string only for out-of-range indices.
static std::wstring char_name(int idx)
{
    if (g_name_provider) {
        std::wstring live;
        if (g_name_provider(idx, live))
            return live;
    }
    const wchar_t* def = DefaultCharName(idx);
    return def ? std::wstring(def) : std::wstring();
}

// (v2.30.17: the token_placeholder() helper that lived here — "[item
// name]"/"[number]" etc. for a supposed 4-byte mid-string dynamic token in
// 0xEB-0xF0 — is GONE. Live raw captures proved those bytes are single-byte
// character-name references in field dialog, same as 0xEA/0xF1/0xF2; see
// the mid-string name branch in decode_walk() for the evidence.)

// Lookup table for FF7 PC US bytes 0x5F-0xDF.
// Sourced from ff7tk (LGPL-3.0), FF7Text.h eng[] table -- the authoritative
// English PC encoding table maintained by the FF7 modding community.
// Array index = byte - 0x5F; L'\0' means no printable glyph for that byte.
//
// WHY: The naive byte+0x20 formula is correct for bytes 0x00-0x5E (maps to
// standard ASCII 0x20-0x7E), but produces wrong Unicode for bytes 0x5F-0xDF.
// For example: byte 0xB5 via byte+0x20 gives U+00D5 (Ó), but FF7 actually
// renders an apostrophe (U+2019). This table gives the correct characters.
static const wchar_t kExtendedChars[0x81] = {
    /* 0x5F */ L'\0',
    /* 0x60 */ L'\xC4',  L'\xC5',  L'\xC7',  L'\xC9',  L'\xD1',  L'\xD6',  L'\xDC',  // Ä Å Ç É Ñ Ö Ü
    /* 0x67 */ L'\xE1',  L'\xE0',  L'\xE2',  L'\xE4',  L'\xE3',  L'\xE5',  L'\xE7',  L'\xE9',  L'\xE8', // á à â ä ã å ç é è
    /* 0x70 */ L'\xEA',  L'\xEB',  L'\xED',  L'\xEC',  L'\xEE',  L'\xEF',  // ê ë í ì î ï
    /* 0x76 */ L'\xF1',  L'\xF3',  L'\xF2',  L'\xF4',  L'\xF6',  L'\xF5',  // ñ ó ò ô ö õ
    /* 0x7C */ L'\xFA',  L'\xF9',  L'\xFB',  L'\xFC',  // ú ù û ü
    /* 0x80 */ L'\x2318',L'\xB0',  L'\xA2',  L'\xA3',  L'\xD9',  L'\xDB',  L'\xB6',  L'\xDF',  // ⌘ ° ¢ £ Ù Û ¶ ß
    /* 0x88 */ L'\xAE',  L'\xA9',  L'\x2122',L'\xB4',  L'\xA8',  L'\x2260',L'\xC6',  L'\xD8',  // ® © ™ ´ ¨ ≠ Æ Ø
    /* 0x90 */ L'\x221E',L'\xB1',  L'\x2264',L'\x2265',L'\xA5',  L'\xB5',  L'\x2202',L'\x3A3', // ∞ ± ≤ ≥ ¥ µ ∂ Σ
    /* 0x98 */ L'\x3A0', L'\x3C0', L'\x2321',L'\xAA',  L'\xBA',  L'\x3A9', L'\xE6',  L'\xF8',  // Π π ⌡ ª º Ω æ ø
    /* 0xA0 */ L'\xBF',  L'\xA1',  L'\xAC',  L'\x221A',L'\x192', L'\x2248',L'\x2206',L'\xAB',  // ¿ ¡ ¬ √ ƒ ≈ ∆ «
    /* 0xA8 */ L'\xBB',  L'\x2026',L'\0',    L'\xC0',  L'\xC3',  L'\xD5',  L'\x152', L'\x153', // » … (empty) À Ã Õ Œ œ
    /* 0xB0 */ L'\x2013',L'\x2014',L'\x201C',L'\x201D',L'\x2018',L'\x2019',L'\xF7',  L'\x25CA',// – — " " ' ' ÷ ◊
    /* 0xB8 */ L'\xFF',  L'\x178', L'\x2044',L'\xA4',  L'\x2039',L'\x203A',L'\xFB01',L'\xFB02',// ÿ Ÿ ⁄ ¤ ‹ › ﬁ ﬂ
    /* 0xC0 */ L'\x25A0',L'\x25AA',L'\x201A',L'\x201E',L'\x2030',L'\xC2',  L'\xCA',  L'\xC1',  // ■ ▪ ‚ „ ‰ Â Ê Á
    /* 0xC8 */ L'\xCB',  L'\xC8',  L'\xCD',  L'\xCE',  L'\xCF',  L'\xCC',  L'\xD3',  L'\xD4',  // Ë È Í Î Ï Ì Ó Ô
    /* 0xD0 */ L'\0',    L'\xD2',  L'\xD9',  L'\xDB',  L'\0',    L'\0',    L'\0',    L'\0',     // (empty) Ò Ù Û (empty×4)
    /* 0xD8 */ L'\0',    L'\0',    L'\0',    L'\0',    L'\0',    L'\0',    L'\0',    L'\0',     // (empty×8)
};

// Maps a decoded wchar_t to its best speakable form for TTS.
// Returns L'\0' for characters that should be discarded (emit a word-boundary
// space in their place).
//
// WHY ACCENTED LATIN PASSES THROUGH: NVDA and SAPI both handle U+00C0-U+00FF
// correctly, pronouncing "é" as "e" or "e accent". These appear in character
// names and some English FF7 dialog. Stripping them would concatenate adjacent
// words ("Cloud but" -> "Cloudbut" if there is no space byte around the accent).
static wchar_t canonical_ch(wchar_t ch)
{
    if (ch >= 0x0020 && ch <= 0x007E) return ch;

    switch (ch) {
    // Curly single quotes and apostrophes -> straight apostrophe.
    // WHY: byte 0xB5 is the FF7 apostrophe -- appears in "I'm", "job's", etc.
    // Without this mapping, apostrophes become spaces ("I m", "job s").
    case 0x2018: case 0x2019: case 0x201A: case 0x201B: return L'\'';
    // Curly double quotes -> straight double quote
    case 0x201C: case 0x201D: case 0x201E:              return L'"';
    // En dash, em dash -> hyphen
    case 0x2013: case 0x2014:                            return L'-';
    // Ellipsis -> period (sentence-break signal for TTS)
    case 0x2026:                                         return L'.';
    // Inverted punctuation -> ASCII equivalents (appear in European dialog)
    case 0x00BF:                                         return L'?';
    case 0x00A1:                                         return L'!';
    // Angle guillemets -> double quote
    case 0x00AB: case 0x00BB:                            return L'"';
    // Single angle guillemets -> apostrophe
    case 0x2039: case 0x203A:                            return L'\'';
    default:
        // Accented Latin (U+00C0-U+00FF): pass through; TTS engines handle them
        if (ch >= 0x00C0 && ch <= 0x00FF) return ch;
        return L'\0'; // discard everything else (math symbols, box-drawing, etc.)
    }
}

wchar_t DecodeChar(unsigned char byte)
{
    // Standard ASCII-aligned range: byte + 0x20 is exact (0x00=' ' .. 0x5E='~').
    // canonical_ch() is an identity map for this range but is applied anyway
    // so the two paths can never drift.
    if (byte <= 0x5E) {
        return canonical_ch(static_cast<wchar_t>(byte + 0x20));
    }
    // Extended range: the ff7tk-sourced table gives the real glyph (byte+0x20
    // is WRONG here — 0xB5 is FF7's apostrophe, not Ó), then canonical_ch
    // folds it to its speakable form (curly quote -> straight apostrophe).
    if (byte <= 0xDF) {
        const wchar_t ch = kExtendedChars[byte - 0x5F];
        return (ch != L'\0') ? canonical_ch(ch) : L'\0';
    }
    // 0xE0+ are newline/token/terminator bytes — never printable name content.
    return L'\0';
}

namespace {

// decode_walk: the shared byte-stream walk behind Decode(), DecodeLines(),
// and DecodeMessagePages(). Returns one RAW (un-canonicalized, untrimmed)
// wstring per segment. A page break (0xE8/0xE9) always ends the current
// segment. When split_lines is true, a newline (0xE0/0xE7) ends it too
// (DecodeLines'/DecodeMessagePages' one-entry-per-screen-line splitting);
// when false, a newline is just a guarded space within the current
// segment (Decode() -- prose word-wraps across newlines within one page).
// Callers that don't care about segment boundaries (Decode()) just join
// the entries back together. Always returns at least one (possibly
// empty) entry.
//
// hard_break_out (optional, v2.30.7): when non-null and split_lines is
// true, appended to at every segment boundary -- true if that boundary
// was a page break (0xE8/0xE9, an author-placed HARD break), false if it
// was a plain newline (0xE0/0xE7, just a soft line wrap). Size is
// segment_count-1 (nothing follows the last segment). DecodeMessagePages()
// uses this to know when a page must end HERE regardless of line count,
// vs. when it's free to keep accumulating lines.
std::vector<std::wstring> decode_walk(const char* encoded_text, bool split_lines,
                                      std::vector<bool>* hard_break_out = nullptr,
                                      std::vector<size_t>* seg_start_out = nullptr)
{
    std::vector<std::wstring> pages;
    pages.emplace_back();
    pages.back().reserve(128);
    if (seg_start_out) seg_start_out->push_back(0);
    if (!encoded_text) return pages;

    const uint8_t* const p_base = reinterpret_cast<const uint8_t*>(encoded_text);
    const uint8_t* p   = p_base;
    bool at_start       = true; // true until the first visible content byte is consumed

    // Safety cap: no real FF7 dialog string approaches 4096 bytes.
    // Prevents runaway reads from stale or garbage pointers.
    const uint8_t* const p_end = p + 4096;

    while (p < p_end && *p != 0xFF) {
        const uint8_t byte = *p;
        std::wstring& result = pages.back();

        // ── Speaker indicator (MUST come before mid-string token check) ────────
        // Bytes 0xEA-0xF2 at the very first position of a dialog string mark the
        // speaking character. They appear as a single byte with no data bytes.
        if (at_start && byte >= 0xEA && byte <= 0xF2) {
            const std::wstring name = char_name(byte - 0xEA);
            if (!name.empty()) {
                result += name;
                result += L": ";
            }
            ++p;
            at_start = false;
        }
        // ── Mid-string character-name reference (single byte, 0xEA-0xF2) ─────
        // v2.30.17: mid-string 0xEB-0xF0 were previously treated as 4-byte
        // "dynamic tokens" ([item name] etc., consuming 3 data bytes) on the
        // strength of an FFNx-derived reading -- while 0xEA (Cloud) and
        // 0xF1/0xF2 (Vincent/Cid) were already single-byte name refs. That
        // split was WRONG for field dialog, proven by two independent raw
        // captures with zero counterexamples:
        //   - Tifa (7th Heaven, 2026-07-23): `57 49 54 48 00 EB 1F B3 E7 E0`
        //     = "WITH " + {Barret} + '?' + '"' + newline + newline. Under
        //     the 4-byte reading, EB CONSUMED the '?', the closing quote,
        //     and a newline as "data", truncating the line to '"Did you
        //     fight with [item name]' -- the player heard "item 1".
        //   - Wedge (train graveyard, 2026-07-20): "Hey [item name] What
        //     about our money?" -- reads naturally as "Hey, {Barret}..."
        //     (the v2.30.6 residual note already suspected exactly this).
        // The character-name range is one CONTIGUOUS run 0xEA-0xF2 (ff7tk
        // eng[] table: CLOUD..CID), same mid-string as at position 0 -- the
        // at_start block above adds the ": " speaker suffix, this one just
        // inlines the name. Live savemap names via char_name() (renames
        // respected, v2.19). If some OTHER field text truly embeds a
        // multi-byte dynamic token in this range, its data bytes will now
        // decode as visible garbage in the debug log and can be
        // re-investigated with evidence -- strictly better than silently
        // eating 3 bytes of real text.
        else if (byte >= 0xEA && byte <= 0xF2) {
            guard_space(result);
            result += char_name(byte - 0xEA);
            result += L' ';
            ++p;
            at_start = false;
        }
        // ── Button icons: Circle, Triangle, Square, Cross ─────────────────────
        // Single-byte tokens; no spoken equivalent. Source: ff7tk eng[] table.
        // WHY SINGLE BYTE: prior code treated 0xF8 as a 3-byte skip, but ff7tk
        // confirms all four button tokens are single bytes (0xF6-0xF9).
        else if (byte >= 0xF6 && byte <= 0xF9) {
            ++p;
            // Do not clear at_start -- button icons precede text, not content.
        }
        // ── Newline ──────────────────────────────────────────────────────────
        // 0xE0: confirmed newline in the PC dialog rawptr data (tested v1.2-v1.7).
        // 0xE7: newline as documented in ff7tk eng[] table.
        // split_lines (DecodeLines() only): a newline ends the segment, same
        // as a page break -- see the doc comment above decode_walk().
        //
        // v2.30.10: only actually split when `result` (the segment so far)
        // has real content. Root cause of the ASK cursor bug incorrectly
        // blamed on index math in v2.30.4/6/9: raw dumps from the 2026-07-21
        // Aeris flower-girl scene (both the 2-option and the plain "Buy
        // one"/"Forget it" window) show EVERY selectable option preceded by
        // an 0xE7 immediately followed by 0xE0 (or, when there's no leading
        // name/quote line, a bare 0xE0 as the very first byte). Splitting on
        // BOTH bytes unconditionally turns that into TWO breaks with nothing
        // between them, inserting a spurious empty entry before every
        // option. The game's own FIRST_LINE/LAST_LINE opcode params count
        // real content lines, not raw break bytes, so they landed on our
        // blank artifact, one slot short of the actual option text --
        // ask_lines[first_line] was always empty or the PREVIOUS option's
        // text, never the option the cursor was actually on. Collapsing
        // consecutive breaks (only creating a new segment when the current
        // one already holds content) reproduces the game's own line count
        // exactly in both 2026-07-21 raw dumps (6->4 and 4->2 entries,
        // matching first_line/last_line in both cases with no other change).
        else if (byte == 0xE0 || byte == 0xE7) {
            if (split_lines) {
                if (!result.empty()) {
                    if (hard_break_out) hard_break_out->push_back(false);
                    pages.emplace_back();
                    if (seg_start_out)
                        seg_start_out->push_back((p + 1) - p_base);
                }
                // else: a break immediately after another break (or as the
                // very first byte) with nothing in between -- collapse, do
                // not emit a spurious blank entry; the still-empty
                // segment's true content now begins after THIS byte, so
                // keep its recorded start in step (v2.30.19 offsets).
                else if (seg_start_out) {
                    seg_start_out->back() = (p + 1) - p_base;
                }
            }
            else guard_space(result);
            ++p;
            at_start = false;
        }
        // ── Page break ───────────────────────────────────────────────────────
        // 0xE8, 0xE9: new-page separators. FF7's rawptr holds the COMPLETE
        // multi-page message from window-open, so these mark where the
        // DISPLAY actually breaks to a fresh screen (v2.30.4: split into a
        // new page entry here instead of flattening to a space -- see
        // DecodeMessagePages() doc comment in ff7_text.h for why).
        else if (byte == 0xE8 || byte == 0xE9) {
            if (hard_break_out) hard_break_out->push_back(true);
            pages.emplace_back();
            if (seg_start_out)
                seg_start_out->push_back((p + 1) - p_base);
            ++p;
            at_start = false;
        }
        // ── Comma ────────────────────────────────────────────────────────────
        // 0xE2: not in any previously-documented range (not a name/token
        // byte, not newline/page-break, above the kExtendedChars table's
        // 0xDF ceiling) -- fell into the "unknown, guard a space" branch
        // below, which just left a GAP where the comma should be ("Say do
        // you" instead of "Say, do you"). v2.30.6: cross-checked ~20
        // independent raw dumps from a single play session (2026-07-20) --
        // 0xE2 appears exactly where a comma reads naturally in every one
        // ("Fine, I'll do it", "What's wrong, Cloud?", "Come on, let's go",
        // "Heads up, here it comes", "Say, do you...") with zero
        // counterexamples. No FFNx/ff7tk table entry names it; this is a
        // live-corpus finding, not a documented source.
        else if (byte == 0xE2) {
            result += L',';
            ++p;
            at_start = false;
        }
        // ── Standard ASCII range ───────────────────────────────────────────────
        else if (byte <= 0x5E) {
            // byte + 0x20 maps 0x00->'space', 0x01->'!', ..., 0x5E->'~'.
            // This is the correct formula for the lower range of FF7's encoding.
            result += static_cast<wchar_t>(byte + 0x20);
            ++p;
            at_start = false;
        }
        // ── Extended characters (lookup table) ────────────────────────────────
        else if (byte <= 0xDF) {
            // Use the kExtendedChars table (sourced from ff7tk) instead of byte+0x20,
            // which produces wrong Unicode for this range. For example, byte 0xB5
            // via byte+0x20 gives U+00D5 (Ó), but the correct character is U+2019
            // (right single quotation mark / apostrophe), as FF7 actually renders.
            const wchar_t ch = kExtendedChars[byte - 0x5F];
            if (ch != L'\0') result += ch;
            ++p;
            at_start = false;
        }
        // ── Unknown / unhandled control byte ─────────────────────────────────
        // v2.30.4: this byte previously vanished with NO output and no
        // compensating space -- if it sits between two words with no
        // explicit space byte around it (which the original renderer never
        // needed, since a non-printing control code isn't a visible glyph),
        // the words fuse ("Uh" + <dropped byte> + "nothin'" -> "Uhnothin'",
        // player report 2026-07-20). Guard the boundary like every other
        // content-affecting byte above.
        else {
            guard_space(result);
            ++p;
        }
    }

    return pages;
}

// ── Character canonicalization filter ─────────────────────────────────────
// Maps Unicode characters to their best speakable ASCII form, keeping
// accented Latin as-is (TTS handles it), and discarding everything that has
// no speech value (mathematical symbols, box-drawing, etc.).
//
// WHY NOT STRIP-ONLY: discarding a non-ASCII character without replacing
// it would concatenate adjacent words ("job's" -> "jobs"). We emit one
// replacement space per run of discarded characters to preserve word
// boundaries, then trim leading/trailing spaces.
std::wstring filter_and_trim(const std::wstring& raw)
{
    std::wstring filtered;
    filtered.reserve(raw.size());
    bool prev_was_replacement = true; // start-of-string acts like a space
    for (wchar_t ch : raw) {
        const wchar_t out = canonical_ch(ch);
        if (out != L'\0') {
            filtered += out;
            prev_was_replacement = false;
        } else if (!prev_was_replacement) {
            filtered += L' ';
            prev_was_replacement = true;
        }
    }

    const std::wstring::size_type first = filtered.find_first_not_of(L' ');
    if (first == std::wstring::npos) return {};
    const std::wstring::size_type last  = filtered.find_last_not_of(L' ');
    return filtered.substr(first, last - first + 1);
}

} // namespace

std::wstring Decode(const char* encoded_text)
{
    if (!encoded_text) return {};

    // Flatten pages back into one string (page breaks read the same as a
    // newline here) -- callers that don't page-pace speech just want the
    // full text, same behavior as before v2.30.4.
    const std::vector<std::wstring> pages = decode_walk(encoded_text, /*split_lines=*/false);
    std::wstring joined;
    for (size_t i = 0; i < pages.size(); ++i) {
        if (i != 0) guard_space(joined);
        joined += pages[i];
    }
    return filter_and_trim(joined);
}

std::vector<std::wstring> DecodeLines(const char* encoded_text)
{
    std::vector<std::wstring> out;
    if (!encoded_text) return out;
    for (const std::wstring& raw : decode_walk(encoded_text, /*split_lines=*/true))
        out.push_back(filter_and_trim(raw));
    return out;
}

// v2.30.7: FF7's own dialog box shows a fixed number of lines at a time
// (4, per widely-documented FF7 window sizing); its RENDERER breaks a page
// there even when the SOURCE TEXT has no explicit page-break byte at that
// point -- player report 2026-07-20: a dialog with real on-screen page
// turns (confirmed by the STATE MACHINE's own PAGE transitions still
// firing) decoded as a single DecodePages() entry because there was no
// 0xE8/0xE9 anywhere in it, so the whole thing spoke at once and every
// later PAGE event found nothing left to say (dead silence, no cue to
// press the button). DecodePages() alone can only ever catch the AUTHOR-
// PLACED hard breaks; it has no way to know where the RENDERER will
// additionally soft-wrap a long unbroken passage.
//
// This is the fix: group decoded LINES (same newline splitting as
// DecodeLines) into pages of up to kLinesPerPage, but still respect an
// explicit page-break byte as a forced early close (some passages use
// deliberately SHORT hard-broken pages for pacing/emphasis, and those
// must not get merged with what follows). Result: dialogs with explicit
// markers behave exactly as before (DecodePages and DecodeMessagePages
// agree whenever a page never exceeds kLinesPerPage lines); dialogs that
// rely purely on the renderer's own overflow wrap now get a page speak
// for every screen the player actually sees, instead of one page and
// then silence.
//
// kLinesPerPage=4 is an ASSUMPTION (FF7's standard message window's
// documented capacity), not a value read from the game -- if a future
// play report shows pages breaking a line early or late relative to what
// is actually on screen, that number is the first thing to revisit.
std::vector<std::wstring> DecodeMessagePages(const char* encoded_text,
                                             std::vector<size_t>* page_offsets_out)
{
    constexpr size_t kLinesPerPage = 4;

    std::vector<std::wstring> out;
    if (page_offsets_out) page_offsets_out->clear();
    if (!encoded_text) return out;

    std::vector<bool> hard_break;
    std::vector<size_t> seg_starts;
    const std::vector<std::wstring> raw_lines =
        decode_walk(encoded_text, /*split_lines=*/true, &hard_break, &seg_starts);

    std::wstring current_page;
    size_t lines_in_page = 0;
    size_t page_first_line = 0;
    for (size_t i = 0; i < raw_lines.size(); ++i) {
        if (lines_in_page == 0) page_first_line = i;
        const std::wstring line = filter_and_trim(raw_lines[i]);
        if (!current_page.empty() && !line.empty()) current_page += L' ';
        current_page += line;
        ++lines_in_page;

        const bool is_hard_break_here = (i < hard_break.size()) && hard_break[i];
        const bool is_last_line       = (i + 1 == raw_lines.size());
        if (is_hard_break_here || lines_in_page >= kLinesPerPage || is_last_line) {
            out.push_back(current_page);
            // v2.30.19: raw byte offset where this page's first line began
            // (seg_starts is index-aligned with raw_lines by construction).
            if (page_offsets_out)
                page_offsets_out->push_back(
                    page_first_line < seg_starts.size()
                        ? seg_starts[page_first_line] : 0);
            current_page.clear();
            lines_in_page = 0;
        }
    }
    if (out.empty()) {
        out.push_back(std::wstring());
        if (page_offsets_out) page_offsets_out->push_back(0);
    }
    return out;
}

} // namespace FF7Text
