/*
 * Tolk.h -- Public C API for Tolk, the screen reader abstraction library.
 *
 * Tolk supports NVDA, JAWS, SAPI, System Access, and Window-Eyes on Windows.
 * This header declares the dllimport signatures. Tolk.dll must be present in
 * the same folder as the loading DLL (our winmm.dll proxy) or on the PATH.
 *
 * Source: https://github.com/dkager/tolk
 * The accessibility mod loads Tolk at runtime via LoadLibrary/GetProcAddress
 * rather than linking against Tolk.lib, so this header is used only for
 * documentation and type-checking the function pointer typedefs in tts.cpp.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tolk_Load: Initialize the Tolk library.
 * Must be called once before any other Tolk function.
 * Automatically detects the active screen reader (NVDA, JAWS, etc.).
 */
void WINAPI Tolk_Load();

/*
 * Tolk_IsLoaded: Returns true if Tolk_Load() has been called successfully.
 */
bool WINAPI Tolk_IsLoaded();

/*
 * Tolk_Unload: Uninitialize Tolk and release all resources.
 * Call this when the host application is shutting down.
 */
void WINAPI Tolk_Unload();

/*
 * Tolk_TrySAPI: If true, Tolk will try Windows SAPI as a last-resort
 * when no dedicated screen reader (NVDA/JAWS) is detected.
 * Call before Tolk_Load() to take effect at initialization.
 */
void WINAPI Tolk_TrySAPI(bool trySAPI);

/*
 * Tolk_PreferSAPI: If true, SAPI is used even when NVDA/JAWS is running.
 * Not typically desired; here for completeness.
 */
void WINAPI Tolk_PreferSAPI(bool preferSAPI);

/*
 * Tolk_DetectScreenReader: Returns the name of the active screen reader
 * (e.g. "NVDA", "JAWS"), or NULL if none is detected.
 * Returned string is owned by Tolk; do not free it.
 */
const wchar_t* WINAPI Tolk_DetectScreenReader();

/*
 * Tolk_HasSpeech: Returns true if the active screen reader supports speech.
 */
bool WINAPI Tolk_HasSpeech();

/*
 * Tolk_HasBraille: Returns true if the active screen reader supports braille output.
 */
bool WINAPI Tolk_HasBraille();

/*
 * Tolk_Output: Send text to both speech and braille simultaneously.
 * str:       Wide string to output. Must not be NULL.
 * interrupt: If true, cancel any currently-playing speech before starting.
 * Returns true on success.
 */
bool WINAPI Tolk_Output(const wchar_t* str, bool interrupt);

/*
 * Tolk_Speak: Send text to the speech synthesizer only (no braille).
 * str:       Wide string to speak. Must not be NULL.
 * interrupt: If true, cancel any currently-playing speech before starting.
 * Returns true on success.
 */
bool WINAPI Tolk_Speak(const wchar_t* str, bool interrupt);

/*
 * Tolk_Braille: Send text to the braille display only (no speech).
 * Returns true on success.
 */
bool WINAPI Tolk_Braille(const wchar_t* str);

/*
 * Tolk_IsSpeaking: Returns true if speech is currently being output.
 */
bool WINAPI Tolk_IsSpeaking();

/*
 * Tolk_Silence: Interrupt and cancel any currently-playing speech.
 * Returns true on success.
 */
bool WINAPI Tolk_Silence();

#ifdef __cplusplus
}
#endif
