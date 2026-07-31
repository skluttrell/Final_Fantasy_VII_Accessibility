/*
 * tones.h -- Audio cue playback for every tone in the mod (v2.30.41).
 *
 * WHY THIS MODULE EXISTS (replacing kernel32 Beep()):
 *   Every audio cue in this mod — the 220 Hz wall thud, 1175 Hz proximity
 *   chirp, 880 Hz wandering cue, and the 1568 Hz dialog wait/choice tones —
 *   was originally played with kernel32's Beep(). A 2026-07-31 tester
 *   report proved Beep() unreliable: their session log showed every tone
 *   code path firing (the "WALL body:" lines print INSIDE the block that
 *   has just called Beep()), yet they heard nothing. Their machine — a
 *   Windows 11 ARM VM on Apple Silicon with a virtual audio device — is
 *   exactly where Beep()'s legacy system-beep route dies silently: it
 *   returns success with no audible output in many VMs, remote sessions,
 *   and when the Volume Mixer's "System Sounds" slider is muted.
 *
 *   Meanwhile the same tester HEARD game audio (DirectSound/FFNx) and NVDA
 *   speech. The fix is therefore to route tones the same way the audio
 *   they can hear already goes: a normal wave stream into the default
 *   render endpoint, via winmm's waveOut* API.
 *
 * WHAT USERS GAIN / WHAT CHANGES:
 *   - VM / remote-session users start hearing tones at all.
 *   - Tones now live in the game process's audio session (the game's
 *     Volume Mixer slider), not "System Sounds" — they scale with the
 *     game's volume while screen-reader speech stays independent.
 *   - Volume is finally controllable: the tone_volume config setting
 *     (0-100) scales every tone; Beep() had a fixed level.
 *   - A 5 ms fade-in/out envelope removes the click at tone edges that
 *     Beep()'s abrupt start/stop produced.
 *
 * BLOCKING SEMANTICS (deliberate — drop-in Beep() replacement):
 *   Play() blocks the CALLING thread until the tone finishes, exactly like
 *   Beep() did. Every call site is a dedicated background polling thread
 *   whose pacing logic (e.g. WallBumpThread's 300 ms repeat gate, the
 *   dialog choice tone's Sleep(60) double-beep gap) was written around a
 *   blocking call; keeping that contract means zero behavioral change at
 *   any call site. Tones must still NEVER be played from a game hook —
 *   the same rule as before (see hooks.cpp's pending-flag pattern).
 *
 * SELF-PROXY SAFETY:
 *   This mod ships as a proxy DLL (version.dll today; a winmm.dll proxy
 *   variant exists in the tree). If it were ever loaded AS winmm.dll,
 *   linking winmm.lib and calling waveOutOpen directly would resolve to
 *   our own exports and recurse. So this module never links winmm: it
 *   LoadLibrary's the REAL System32 winmm.dll by absolute path (the same
 *   technique winmm_proxy.cpp documents) and calls through GetProcAddress
 *   pointers. This also keeps the CMake link list unchanged.
 *
 * FALLBACK:
 *   If the real winmm cannot be loaded, or any waveOut call fails at
 *   runtime (no audio device, endpoint in exclusive use), Play() falls
 *   back to Beep() — no system ever behaves WORSE than pre-v2.30.41.
 */

#pragma once

namespace Tones {

// Resolve waveOut* from the real System32 winmm.dll and log the outcome.
// Call once at startup, after Log::Init() (so the ready/fallback line is
// captured) and before any thread that can call Play() is created.
// Idempotent; safe to call again (subsequent calls are no-ops).
void Init();

// Play a tone of the given frequency and duration, blocking the calling
// thread until it completes — a drop-in replacement for Beep(freq, ms).
// Volume comes from Config::Get().tone_volume (0 = all tones silenced).
// Never call from a game hook; background polling threads only.
void Play(unsigned freq_hz, unsigned dur_ms);

// NOTE: there is deliberately no Shutdown()/FreeLibrary. The real winmm
// module stays pinned for the process lifetime: background tone threads
// are joined with 500 ms TIMEOUTS during Proxy::Shutdown(), so a slow
// thread could still be inside waveOutWrite when shutdown proceeds —
// unmapping winmm at that moment would crash. Pinning one System32 module
// that the process almost certainly has loaded anyway is free; the OS
// reclaims everything at process exit.

} // namespace Tones
