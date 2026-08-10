/*
 * settings_menu.cpp -- F8 in-game audio-only accessibility menu (v2.30.42).
 * See settings_menu.h for the design rationale (why F8, why J/L/K/I, why
 * the naming screen is the one stand-down context).
 *
 * STRUCTURE:
 *   A table of entries drives everything: each entry knows its cfg key,
 *   its spoken name, its kind (bool / volume / direction-style), a
 *   pointer-to-member into Config::Settings for bools, and a one-line
 *   description for the I key. Adding a future setting to the menu is one
 *   table row (plus the usual cfg list+glossary edit per the v2.30.39
 *   rule).
 *
 * LIVE APPLY + LIVE SAVE:
 *   A change writes the Config::Settings field first (every consumer
 *   re-reads Config::Get() at its point of use, so the new value is live
 *   within one poll of the affected feature), then persists it with
 *   Config::SaveSetting() (single-line in-place rewrite of the cfg). If
 *   the save fails (read-only install dir), the user hears the value
 *   announcement followed by a warning that the change lasts only until
 *   the game closes — the in-memory change stays, matching the promise
 *   the announcement just made.
 *
 * SPECIAL CASES:
 *   debug_log   — the only setting whose consumer does NOT poll: the log
 *                 file handle was opened (or not) once at startup. The
 *                 menu calls Log::SetEnabled() so the toggle acts NOW.
 *   tone_volume — after announcing the new value, a sample tone plays at
 *                 that volume so the user hears the loudness they just
 *                 picked instead of having to walk into a wall to test.
 *   interrupt   — menu speech honors it like all other speech (TTS::Speak
 *                 ANDs our interrupt flag with the setting); with
 *                 interrupt=false, fast browsing queues announcements.
 *                 That is the user's stated preference, not a bug.
 */

#include "settings_menu.h"
#include "config.h"
#include "tts.h"
#include "tones.h"
#include "log.h"
#include "ff7_addresses.h"

#include <string>

namespace SettingsMenu {

namespace {

// ---------------------------------------------------------------------------
// The settings table.
// ---------------------------------------------------------------------------
enum class Kind {
    Bool,       // on/off; any change key toggles
    Volume,     // tone_volume: 0..100 in steps of 10; down/up directional
    DirStyle,   // direction_style: the turn_by_turn bool spoken as a word
};

struct Entry {
    const char*    cfg_key;   // exact key written to ffvii_accessibility.cfg
    const wchar_t* name;      // spoken name
    Kind           kind;
    bool Config::Settings::*flag;  // Bool entries; nullptr otherwise
    const wchar_t* desc;      // spoken by the I key — ONE short sentence
};

// Order: the tone family first (the settings a player reaches for most
// while actually playing), then speech, then navigation, then the rest.
// tone_volume leads because it is the newest knob and the only graded one.
const Entry kEntries[] = {
    { "tone_volume", L"Tone volume", Kind::Volume, nullptr,
      L"Loudness of all the mod's tones, 0 to 100. 0 silences every tone." },
    { "wall_bump_tone", L"Wall bump tone", Kind::Bool,
      &Config::Settings::wall_bump_tone,
      L"Low repeating tone while you push against a wall or a person." },
    { "proximity_tone", L"Proximity tone", Kind::Bool,
      &Config::Settings::proximity_tone,
      L"Single chirp when something you can use comes into reach." },
    { "proximity_announce", L"Say what you reached", Kind::Bool,
      &Config::Settings::proximity_announce,
      L"Speaks the name of what you walk up to, like a ladder or a person." },
    { "dialog_wait_tone", L"Dialog wait tone", Kind::Bool,
      &Config::Settings::dialog_wait_tone,
      L"Tone when a dialog finishes its text and waits for your button." },
    { "dialog_choice_tone", L"Dialog choice tone", Kind::Bool,
      &Config::Settings::dialog_choice_tone,
      L"Double tone the moment a choice menu appears." },
    { "speak_dialog", L"Story dialog speech", Kind::Bool,
      &Config::Settings::speak_dialog,
      L"Reads story dialog aloud. Turn off if you use a voice acting mod." },
    { "speak_choices", L"Choice speech", Kind::Bool,
      &Config::Settings::speak_choices,
      L"Reads choice options as the cursor moves between them." },
    { "speak_battle", L"Battle action speech", Kind::Bool,
      &Config::Settings::speak_battle,
      L"Announces battle actions as they happen." },
    { "speak_battle_damage", L"Battle damage speech", Kind::Bool,
      &Config::Settings::speak_battle_damage,
      L"Speaks damage and healing numbers on the attack's own line in battle." },
    { "speak_battle_status", L"Battle status speech", Kind::Bool,
      &Config::Settings::speak_battle_status,
      L"Speaks status effects gained or cured in battle, like poison or sleep." },
    { "speak_battle_menu", L"Battle menu speech", Kind::Bool,
      &Config::Settings::speak_battle_menu,
      L"Narrates the in-battle command menu and target selection." },
    // v2.30.107: the two Tifa-reel methods (the lead tuner
    // limit_reel_tone_lead stays cfg-file-only — the F8 menu has no
    // millisecond editor and the default suits most reaction times).
    { "limit_reel_tone", L"Limit reel timing tone", Kind::Bool,
      &Config::Settings::limit_reel_tone,
      L"Tone before a Yeah reaches the marker on Tifa's limit reels." },
    { "limit_reel_speak", L"Limit reel spoken results", Kind::Bool,
      &Config::Settings::limit_reel_speak,
      L"Speaks Yeah, Hit, or Miss as each of Tifa's reels stops." },
    { "speak_menus", L"Menu speech", Kind::Bool,
      &Config::Settings::speak_menus,
      L"Narrates the title screen and all game menus." },
    { "speak_enemy_hp_always", L"Enemy HP without Sense", Kind::Bool,
      &Config::Settings::speak_enemy_hp_always,
      L"Speaks enemy HP even before Sense reveals it." },
    { "pathfinder_keys", L"Pathfinder keys", Kind::Bool,
      &Config::Settings::pathfinder_keys,
      L"The J, K, and L destination browser on field maps." },
    { "direction_style", L"Direction style", Kind::DirStyle, nullptr,
      L"Turns speaks a walking route. Line speaks the straight direction." },
    { "announce_map_change", L"Screen change announcements", Kind::Bool,
      &Config::Settings::announce_map_change,
      L"Announces the screen name when you walk into a new area." },
    { "gamepad_nav", L"Gamepad navigation", Kind::Bool,
      &Config::Settings::gamepad_nav,
      L"Right analog stick drives the pathfinder." },
    { "timer_announcements", L"Timer announcements", Kind::Bool,
      &Config::Settings::timer_announcements,
      L"Automatic countdown announcements during timed escapes." },
    { "interrupt", L"Speech interrupt", Kind::Bool,
      &Config::Settings::interrupt,
      L"New speech cuts off speech that is still playing." },
    { "debug_log", L"Debug log", Kind::Bool,
      &Config::Settings::debug_log,
      L"Writes a diagnostic log file for bug reports." },
};
constexpr int kEntryCount = static_cast<int>(sizeof(kEntries) / sizeof(kEntries[0]));

// Menu-open flag, shared with proxy.cpp's key handlers. LONG (not bool)
// so the cross-thread visibility story is the same as every other flag
// in this codebase: aligned 32-bit, volatile, single writer.
volatile LONG s_open = 0;

// ---------------------------------------------------------------------------
// Spoken-value helpers.
// ---------------------------------------------------------------------------
std::wstring ValueText(const Entry& e)
{
    const Config::Settings& s = Config::Get();
    switch (e.kind) {
        case Kind::Volume:   return std::to_wstring(s.tone_volume);
        case Kind::DirStyle: return s.turn_by_turn ? L"turns" : L"line";
        case Kind::Bool:     return (s.*(e.flag)) ? L"on" : L"off";
    }
    return L"";   // unreachable; MSVC wants the path
}

// interrupt=false exists for the open sequence, where this announcement
// must QUEUE behind the key-help sentence spoken a moment earlier — two
// interrupt=true utterances back-to-back would cut the help off after a
// word. Everywhere else (navigation, K, value changes) interrupting is
// exactly what a fast-browsing user wants.
void AnnounceEntry(int idx, bool with_position, bool interrupt = true)
{
    const Entry& e = kEntries[idx];
    std::wstring msg = std::wstring(e.name) + L": " + ValueText(e) + L".";
    if (with_position) {
        msg += L" Setting " + std::to_wstring(idx + 1) + L" of " +
               std::to_wstring(kEntryCount) + L".";
    }
    TTS::Speak(msg, interrupt);
}

// ---------------------------------------------------------------------------
// Apply a change to entry idx. dir is -1 (Shift+J / '-') or +1
// (Shift+L / '='); bools and direction_style toggle regardless of
// direction — with two states, "next" and "previous" both mean "the
// other one", and making one of the two chords a no-op would read as
// breakage to the user.
// ---------------------------------------------------------------------------
void ChangeEntry(int idx, int dir)
{
    const Entry& e = kEntries[idx];
    Config::Settings& s = Config::GetMutable();

    char save_value[16] = {};
    switch (e.kind) {
        case Kind::Volume: {
            int v = s.tone_volume + dir * 10;
            if (v < 0)   v = 0;
            if (v > 100) v = 100;
            s.tone_volume = v;
            _snprintf_s(save_value, sizeof(save_value), _TRUNCATE, "%d", v);
            break;
        }
        case Kind::DirStyle:
            s.turn_by_turn = !s.turn_by_turn;
            _snprintf_s(save_value, sizeof(save_value), _TRUNCATE, "%s",
                        s.turn_by_turn ? "turns" : "line");
            break;
        case Kind::Bool: {
            const bool now = !(s.*(e.flag));
            s.*(e.flag) = now;
            _snprintf_s(save_value, sizeof(save_value), _TRUNCATE, "%s",
                        now ? "true" : "false");
            // debug_log's consumer holds a file handle opened at startup —
            // the only setting where "consumers re-read the config" is not
            // enough. Flip the file NOW so the toggle keeps the menu's
            // no-restart promise.
            if (e.flag == &Config::Settings::debug_log)
                Log::SetEnabled(now);
            break;
        }
    }

    // Speak the result before the disk write: the write is fast but the
    // user's feedback should be instant, and on failure we FOLLOW UP
    // rather than delay every successful change for the rare failure.
    AnnounceEntry(idx, /*with_position=*/false);

    const bool saved = Config::SaveSetting(e.cfg_key, save_value);
    if (!saved) {
        TTS::Speak(L"Could not save to the config file. "
                   L"This change lasts until the game closes.",
                   /*interrupt=*/false);
        Log::Write("[FF7Access] SETTINGS save FAILED (cfg not writable?)");
    }

    if (Config::Get().debug_log) {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] SETTINGS %s = %s%s",
            e.cfg_key, save_value, saved ? "" : " (save failed)");
        Log::Write(dbg);
    }

    // Volume gets an immediate demo at the new level — the wander-cue
    // pitch (880 Hz), long enough to judge loudness, short enough to stay
    // out of the way. Played AFTER Speak (speech is async, so the tone
    // overlaps the start of the announcement instead of delaying it —
    // the same ordering the pathfinder's wandering cue uses).
    if (e.kind == Kind::Volume)
        Tones::Play(880, 120);
}

// ---------------------------------------------------------------------------
// The polling thread.
// ---------------------------------------------------------------------------
DWORD WINAPI MenuThread(LPVOID param)
{
    const HANDLE stop_event = static_cast<HANDLE>(param);
    // 40ms: snappier than the 50ms feature threads because this is a
    // direct-manipulation UI (a laggy menu feels broken to a screen
    // reader user), still far too slow to matter as load.
    constexpr DWORD kPollMs = 40;

    // Tracked VKs. Brackets/minus/equals are the same OEM keys the
    // pathfinder uses for its aliases, so the two features feel like one
    // key scheme (accessiblity_keys.txt parity).
    enum { KF8, KJ, KL, KK, KI, KLBRACKET, KRBRACKET, KMINUS, KPLUS,
           KEY_COUNT };
    static const int kVKs[KEY_COUNT] = {
        VK_F8, 'J', 'L', 'K', 'I',
        VK_OEM_4 /*[*/, VK_OEM_6 /*]*/, VK_OEM_MINUS, VK_OEM_PLUS,
    };
    bool was_down[KEY_COUNT] = {};

    int selection = 0;   // persists across open/close within the session:
                         // reopening lands on the setting last worked with
                         // (cheap continuity for "toggle, test, toggle
                         // back" loops like wall-tone comparisons).

    for (;;) {
        if (WaitForSingleObject(stop_event, kPollMs) == WAIT_OBJECT_0)
            break;

        // Focus gate — same rule as every hotkey in the mod:
        // GetAsyncKeyState is global, and F8/J/L pressed into another
        // window must do nothing here. Key state still updates while
        // unfocused so re-focusing cannot manufacture a stale edge.
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());

        bool pressed[KEY_COUNT] = {};
        bool any = false;
        for (int k = 0; k < KEY_COUNT; ++k) {
            const bool down = (GetAsyncKeyState(kVKs[k]) & 0x8000) != 0;
            pressed[k] = focused && down && !was_down[k];
            was_down[k] = down;
            any = any || pressed[k];
        }

        // Naming screen: J/L/K/I are LETTERS there — they type into the
        // name box no matter what we do (a proxy DLL cannot eat keys).
        // The menu refuses to open and auto-closes, with speech, so the
        // user is never silently mode-switched.
        const uint8_t game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
        const bool naming = (game_mode == FF7Addr::GAME_MODE_NAME_ENTRY);
        if (naming && s_open) {
            InterlockedExchange(&s_open, 0);
            TTS::Speak(L"Accessibility menu closed.", /*interrupt=*/true);
            Log::Write("[FF7Access] SETTINGS menu auto-closed (naming screen)");
        }

        if (!any)
            continue;

        const bool shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
        const bool ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        if (ctrl)
            continue;   // Ctrl chords belong to other features (parity file
                        // reserves Ctrl+\ etc.); never respond to them.

        // ---- F8: toggle ---------------------------------------------------
        if (pressed[KF8]) {
            if (s_open) {
                InterlockedExchange(&s_open, 0);
                TTS::Speak(L"Accessibility menu closed.", /*interrupt=*/true);
            } else if (naming) {
                // Spoken refusal beats silent failure: the user learns the
                // rule instead of concluding the key is broken.
                TTS::Speak(L"Accessibility menu is not available on the "
                           L"naming screen.", /*interrupt=*/true);
            } else {
                InterlockedExchange(&s_open, 1);
                // Full key help on every open: this menu is used rarely
                // (settings churn is occasional), so assuming the user
                // remembers the chords from last week optimizes for the
                // wrong case. One sentence, then the current setting.
                TTS::Speak(L"Accessibility menu. J and L move between "
                           L"settings. Shift J and Shift L change a "
                           L"setting. K repeats, I describes, F8 closes.",
                           /*interrupt=*/true);
                // Queued (interrupt=false) so the help line above is
                // heard in full; see AnnounceEntry's comment.
                AnnounceEntry(selection, /*with_position=*/true,
                              /*interrupt=*/false);
                Log::Write("[FF7Access] SETTINGS menu opened");
            }
            continue;   // F8 never doubles as an in-menu action
        }

        if (!s_open)
            continue;

        // ---- in-menu actions (same verb layout as the pathfinder) --------
        const bool act_prev = (pressed[KJ] && !shift) || pressed[KLBRACKET];
        const bool act_next = (pressed[KL] && !shift) || pressed[KRBRACKET];
        const bool act_dec  = (pressed[KJ] && shift)  || pressed[KMINUS];
        const bool act_inc  = (pressed[KL] && shift)  || pressed[KPLUS];
        const bool act_say  = pressed[KK];
        const bool act_desc = pressed[KI];

        if (act_prev || act_next) {
            selection = (selection + (act_next ? 1 : kEntryCount - 1))
                        % kEntryCount;
            AnnounceEntry(selection, /*with_position=*/true);
        } else if (act_dec || act_inc) {
            ChangeEntry(selection, act_inc ? +1 : -1);
        } else if (act_say) {
            AnnounceEntry(selection, /*with_position=*/true);
        } else if (act_desc) {
            TTS::Speak(kEntries[selection].desc, /*interrupt=*/true);
        }
    }

    return 0;
}

} // anonymous namespace

HANDLE Start(HANDLE stop_event)
{
    return CreateThread(nullptr, 0, MenuThread, stop_event, 0, nullptr);
}

bool IsOpen()
{
    return s_open != 0;
}

} // namespace SettingsMenu
