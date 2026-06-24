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

    while (*p != 0xFF) {
        const uint8_t byte = *p;

        if (byte >= 0xEA && byte <= 0xF2) {
            // Character name token. These single bytes represent a character's name.
            // At the start of a string they indicate the speaking character.
            // Mid-string they are unusual but still decoded as the name.
            const int name_idx = byte - 0xEA;
            if (name_idx < kCharNameCount) {
                if (at_start) {
                    // Format as "CharName: " — the colon and space separate the
                    // speaker's name from the dialog text that follows.
                    result += kCharNames[name_idx];
                    result += L": ";
                } else {
                    result += kCharNames[name_idx];
                }
            }
            ++p;
            at_start = false;
        }
        else if (byte >= 0xEB && byte <= 0xEF) {
            // 4-byte dynamic token: [token_byte][data0][data1][data2].
            // This range overlaps with character name tokens 0xEB–0xEF, but
            // when used as a dynamic token the 3 following bytes are data bytes.
            // We emit a human-readable placeholder so the TTS output still
            // makes grammatical sense.
            result += token_placeholder(byte);
            // Skip the 3 data bytes that follow the token header.
            p += 4;
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

    // Trim trailing whitespace (newlines at the end of dialog produce trailing spaces).
    while (!result.empty() && result.back() == L' ') {
        result.pop_back();
    }

    return result;
}

} // namespace FF7Text
