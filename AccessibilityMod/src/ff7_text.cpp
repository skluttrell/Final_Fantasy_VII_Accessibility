/*
 * ff7_text.cpp -- Implementation of FF7 text decoding.
 * See ff7_text.h for the full encoding specification.
 */

#include "ff7_text.h"
#include <cstdint>

namespace FF7Text {

// Default English character names, indexed by the low nibble of the token byte.
// Token 0xEA=Cloud, 0xEB=Barret, ..., 0xF2=Cid.
// The token byte minus 0xEA gives the index into this array.
// Future improvement: read the actual names from the savemap at runtime, as
// the player can rename characters at the beginning of the game.
static const wchar_t* const kCharNames[] = {
    L"Cloud",   // 0xEA
    L"Barret",  // 0xEB
    L"Tifa",    // 0xEC
    L"Aerith",  // 0xED
    L"Red XIII",// 0xEE
    L"Yuffie",  // 0xEF
    L"Cait Sith",// 0xF0
    L"Vincent", // 0xF1
    L"Cid",     // 0xF2
};
static constexpr int kCharNameCount = sizeof(kCharNames) / sizeof(kCharNames[0]);

// The dynamic tokens in the 0xEB–0xEF range have two uses:
//   1. At string index 0 (first byte), they indicate the speaking character.
//   2. Mid-string (after index 0), they are 4-byte dynamic tokens where the
//      following 3 bytes encode the type and value of the placeholder.
//
// We distinguish by tracking whether we've seen any non-token characters yet.
// If the token is the very first byte and it maps to a character name, we
// treat it as a speaker indicator and prepend "[Name]: ".
// Otherwise we emit a human-readable placeholder.

// Placeholders for dynamic tokens that we cannot fully resolve in v1.
// The token type byte (the byte immediately after the token prefix) determines
// which of these to use. Source: voice.cpp decode_ff7_text() special cases.
static const wchar_t* token_placeholder(uint8_t token_byte)
{
    switch (token_byte) {
    case 0xEB: return L"[item name]";
    case 0xEC: return L"[number]";
    case 0xED: return L"[target]";
    case 0xEE: return L"[attack]";
    case 0xEF: return L"[special]";
    case 0xF0: return L"[target letter]";  // Source: FFNx voice.cpp case 0xF0
    default:   return L"[...]";
    }
}

std::wstring Decode(const char* encoded_text)
{
    if (!encoded_text) return {};

    std::wstring result;
    result.reserve(128); // Most dialog strings are under 128 characters.

    const uint8_t* p = reinterpret_cast<const uint8_t*>(encoded_text);
    bool at_start = true; // Used to detect speaker-name tokens at position 0.

    // Safety cap: FF7 dialog strings are never more than a few hundred bytes.
    // Without this limit, a stale or garbage pointer (e.g. freed text from
    // the Echo-S intro still held in DIALOG_TEXT_PTRS) would run the loop
    // into unmapped memory, causing an access violation. 4096 bytes is a
    // safe upper bound that no real FF7 string will approach.
    const uint8_t* const p_end = p + 4096;

    while (p < p_end && *p != 0xFF) {
        const uint8_t byte = *p;

        if (at_start && byte >= 0xEA && byte <= 0xF2) {
            // Speaker indicator: a character name token as the FIRST byte of dialog.
            // 0xEA=Cloud, 0xEB=Barret, ..., 0xF2=Cid. Single byte, no data bytes.
            // Format as "CharName: " to separate speaker from dialog text.
            const int name_idx = byte - 0xEA;
            if (name_idx < kCharNameCount) {
                result += kCharNames[name_idx];
                result += L": ";
            }
            ++p;
            at_start = false;
        }
        else if (byte >= 0xEB && byte <= 0xF0) {
            // Mid-string dynamic token: [type_byte][data0][data1][data2] — 4 bytes total.
            // The same byte values 0xEB-0xEF serve as speaker indicators at position 0
            // (handled above) but are 4-byte dynamic tokens everywhere else.
            // 0xF0 is "target letter" — only appears mid-string, no speaker use.
            // Source: FFNx voice.cpp decode_ff7_text cases 0xEB-0xF0.
            //
            // WHY THIS BRANCH MUST COME BEFORE THE NORMAL-CHAR BRANCH:
            //   Without this, the data bytes following the token header would be
            //   decoded as normal characters (byte+0x20), producing garbage like
            //   the "ö­ù" prefix observed before character name outputs.
            result += token_placeholder(byte);
            p += 4;  // skip type byte + 3 data bytes
            at_start = false;
        }
        else if (byte == 0xEA) {
            // 0xEA mid-string: inline reference to the current party leader's name.
            // In most runs this is Cloud; v1 hardcodes the default since reading
            // the savemap rename is deferred to v2.
            result += kCharNames[0];  // Cloud
            ++p;
            at_start = false;
        }
        else if (byte >= 0xF1 && byte <= 0xF2) {
            // 0xF1=Vincent, 0xF2=Cid appearing mid-string. Rare but possible when
            // a character name is referenced inline in dialog text.
            const int name_idx = byte - 0xEA;
            if (name_idx < kCharNameCount) {
                result += kCharNames[name_idx];
            }
            ++p;
            at_start = false;
        }
        else if (byte == 0xF8) {
            // Formatting skip token: consume this byte and the following 2 data bytes.
            // These bytes control text rendering features (color, animation, etc.)
            // that have no speech equivalent.
            p += 3;
            // Do not clear at_start — this token doesn't count as visible content.
        }
        else if (byte == 0xE0) {
            // Newline. Replace with a single space so the screen reader reads
            // across line breaks naturally without an awkward pause or literal "newline".
            if (!result.empty() && result.back() != L' ') {
                result += L' ';
            }
            ++p;
            at_start = false;
        }
        else if (byte <= 0xDF) {
            // Normal printable character. The FF7 encoding offsets by 0x20 from ASCII.
            // So encoded 0x00 = ASCII 0x20 (space), 0x21 = 'A', etc.
            result += static_cast<wchar_t>(byte + 0x20);
            ++p;
            at_start = false;
        }
        else {
            // Unknown byte — skip it to avoid producing garbage in speech output.
            ++p;
        }
    }

    // TEMPORARY ASCII FILTER:
    // Many FF7 bytes in the 0x5F-0xDF range decode incorrectly via byte+0x20
    // (e.g., 0xB2 → U+00D2 'Ò' instead of the left curly quote FF7 actually renders,
    // 0xB5 → U+00D5 'Õ' instead of apostrophe). There are also 3-byte window-style
    // header sequences (e.g., 0xD6 ?? 0xD9) at the start of some dialogs that decode
    // to extended Latin characters. All of these produce garbled TTS output.
    //
    // Until a proper lookup table is in place, strip every character outside printable
    // ASCII (U+0020–U+007E) and replace it with a space to preserve word boundaries.
    // Consecutive non-ASCII characters produce only a single replacement space.
    //
    // WHY NOT JUST STRIP (leave nothing): stripping without spacing would concatenate
    // adjacent words ("Cloud" + "Cloud Strife" → "CloudCloud Strife") which TTS reads
    // as one word. A replacement space keeps words audibly separate.
    std::wstring filtered;
    filtered.reserve(result.size());
    bool prev_was_space = true; // treat virtual start-of-string as space
    for (wchar_t ch : result) {
        if (ch >= 0x0020 && ch <= 0x007E) {
            filtered += ch;
            prev_was_space = (ch == L' ');
        } else if (!prev_was_space) {
            filtered += L' ';
            prev_was_space = true;
        }
        // Else: consecutive non-ASCII after a space — skip (no double spaces).
    }

    // Trim leading and trailing spaces introduced by the filter.
    const std::wstring::size_type first = filtered.find_first_not_of(L' ');
    if (first == std::wstring::npos) return {}; // all whitespace
    const std::wstring::size_type last = filtered.find_last_not_of(L' ');
    return filtered.substr(first, last - first + 1);
}

} // namespace FF7Text
