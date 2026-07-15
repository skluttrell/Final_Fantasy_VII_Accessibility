/*
 * ff7_text.cpp -- FF7 custom text encoding -> wstring for TTS output.
 * See ff7_text.h for the encoding specification overview.
 */

#include "ff7_text.h"
#include <cstdint>

namespace FF7Text {

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

// Tokens 0xEB-0xF0 have two uses depending on position:
//   - At string index 0: speaker indicator (handled in the at_start block below)
//   - Mid-string: 4-byte dynamic token ([type_byte][d0][d1][d2])
// This returns the placeholder for mid-string use.
static const wchar_t* token_placeholder(uint8_t token_byte)
{
    switch (token_byte) {
    case 0xEB: return L"[item name]";
    case 0xEC: return L"[number]";
    case 0xED: return L"[target]";
    case 0xEE: return L"[attack]";
    case 0xEF: return L"[special]";
    case 0xF0: return L"[target letter]";
    default:   return L"[...]";
    }
}

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

std::wstring Decode(const char* encoded_text)
{
    if (!encoded_text) return {};

    std::wstring result;
    result.reserve(128);

    const uint8_t* p   = reinterpret_cast<const uint8_t*>(encoded_text);
    bool at_start       = true; // true until the first visible content byte is consumed

    // Safety cap: no real FF7 dialog string approaches 4096 bytes.
    // Prevents runaway reads from stale or garbage pointers.
    const uint8_t* const p_end = p + 4096;

    while (p < p_end && *p != 0xFF) {
        const uint8_t byte = *p;

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
        // ── Mid-string dynamic token (4-byte: header + 3 data bytes) ──────────
        // Bytes 0xEB-0xF0 mid-string are NOT single-byte speaker indicators --
        // they head a 4-byte token encoding a dynamic value (item name, number,
        // attack name, etc.). Source: FFNx voice.cpp decode_ff7_text cases.
        // WHY CHECK at_start ABOVE FIRST: without the at_start guard, 0xEB
        // (Barret) at position 0 would be consumed here as a dynamic token,
        // emitting "[item name]" instead of "Barret: ".
        else if (byte >= 0xEB && byte <= 0xF0) {
            result += token_placeholder(byte);
            p += 4;
            at_start = false;
        }
        // ── Inline Cloud name reference (mid-string) ──────────────────────────
        else if (byte == 0xEA) {
            // 0xEA mid-string = Cloud's name (character record 0) — the live
            // savemap name via char_name(), so renames are respected (v2.19).
            result += char_name(0);
            ++p;
            at_start = false;
        }
        // ── Mid-string Vincent / Cid reference ────────────────────────────────
        else if (byte == 0xF1 || byte == 0xF2) {
            result += char_name(byte - 0xEA);
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
        // ── Newline / page break ───────────────────────────────────────────────
        // 0xE0: confirmed newline in the PC dialog rawptr data (tested v1.2-v1.7).
        // 0xE7: newline as documented in ff7tk eng[] table.
        // 0xE8, 0xE9: new-page separators -- treated as whitespace for TTS;
        //             actual page-advance TTS is driven by state machine transitions.
        else if (byte == 0xE0 || byte == 0xE7 || byte == 0xE8 || byte == 0xE9) {
            if (!result.empty() && result.back() != L' ') result += L' ';
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
        else {
            ++p;
        }
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
    std::wstring filtered;
    filtered.reserve(result.size());
    bool prev_was_replacement = true; // start-of-string acts like a space
    for (wchar_t ch : result) {
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

} // namespace FF7Text
