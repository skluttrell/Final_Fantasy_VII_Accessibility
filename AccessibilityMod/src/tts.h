/*
 * tts.h -- Screen reader output wrapper using Tolk.
 *
 * Tolk is loaded at runtime via LoadLibrary/GetProcAddress rather than linked
 * via Tolk.lib. This allows the mod to start even if Tolk.dll is absent —
 * the game runs normally, TTS is simply silent — and avoids import-table
 * dependencies that could cause the process to fail to start.
 *
 * Speak() and Silence() are safe to call from multiple threads. They serialize
 * through an internal CRITICAL_SECTION (g_speak_cs in tts.cpp). Callers include
 * the game's main thread (via hook functions) and TitleCursorThread.
 */

#pragma once
#include <string>

namespace TTS {

/*
 * Init: Load Tolk.dll from the FF7 install folder and initialize it.
 *
 * Tolk auto-detects the running screen reader (NVDA, JAWS, SAPI).
 * If Tolk.dll is not found, this function fails silently — all subsequent
 * Speak/Silence calls become no-ops.
 *
 * Must be called after Config::Load() so that SAPI fallback behavior is known.
 * Should be called from the game's main thread (after the game has initialized)
 * rather than from DllMain, to avoid DLL loader lock complications.
 */
void Init();

/*
 * Speak: Send text to the active screen reader.
 *
 * text:      The wide string to speak. Empty strings are ignored.
 * interrupt: If true, cancels currently-playing speech before starting.
 *            Use true for navigation events (menu cursor move, new dialog page).
 *            Use false when queuing supplemental information.
 *
 * Respects Config::Get().interrupt as a global override: if the user has set
 * interrupt=false in the config file, this parameter is treated as false
 * regardless of the caller's argument.
 */
void Speak(const wchar_t* text, bool interrupt = true);

// Convenience overload for std::wstring.
inline void Speak(const std::wstring& text, bool interrupt = true) {
    Speak(text.c_str(), interrupt);
}

/*
 * Silence: Cancel any currently-playing speech immediately.
 * No-op if Tolk is not initialized or not playing anything.
 */
void Silence();

/*
 * Shutdown: Uninitialize Tolk and unload Tolk.dll.
 * Called from DllMain on DLL_PROCESS_DETACH.
 */
void Shutdown();

} // namespace TTS
