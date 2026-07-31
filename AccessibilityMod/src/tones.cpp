/*
 * tones.cpp -- waveOut tone synthesis (v2.30.41). See tones.h for the full
 * rationale (Beep() proven silent on a tester's VM while waveOut-routed
 * audio was audible; blocking semantics kept as a drop-in replacement).
 *
 * DESIGN CHOICES, AND WHY:
 *
 *   Per-call waveOutOpen (not a cached handle):
 *     Beep() silently follows the Windows default output device when the
 *     user switches it mid-session; a cached waveOut handle keeps playing
 *     to the OLD device (or starts failing). Opening WAVE_MAPPER fresh for
 *     each tone restores Beep()'s follow-the-default behavior. Cost is
 *     negligible at this mod's tone rates (the fastest producer is the
 *     wall thud at ~3 tones/second; device open is well under a
 *     millisecond of CPU, and the audio engine mixes in shared mode).
 *
 *   Per-call synthesis buffer:
 *     Tones are 50-70 ms of 16-bit mono at 44.1 kHz — a few KB. Building
 *     the sine on the stack-side vector per call keeps Play() stateless
 *     and thread-safe by construction (wall, dialog-tone, and nav threads
 *     can all be inside Play() simultaneously, each with its own device
 *     handle and buffer; the audio engine mixes overlapping tones).
 *
 *   Volume curve — amplitude = full-scale * (tone_volume/100)^2:
 *     A linear amplitude slider sounds wildly non-linear to the ear (the
 *     step 90->100 is inaudible, 0->10 is huge). Squaring the fraction
 *     approximates perceptually even steps across the 0-100 range without
 *     pulling in a full dB mapping. Default 60 -> 0.36 of full scale
 *     (~ -9 dB), chosen to sit near Beep()'s perceived loudness on a
 *     typical system rather than blasting a full-scale sine.
 *
 *   5 ms linear fade-in/out INSIDE the requested duration:
 *     A sine that starts/stops at a non-zero sample is a click (a step
 *     discontinuity spreads energy across the spectrum). Beep() audibly
 *     clicks for exactly this reason. 5 ms is short enough to keep the
 *     50 ms tones percussive but long enough to kill the click. The fade
 *     lives inside dur_ms so total timing matches Beep(freq, dur_ms) and
 *     no call-site pacing changes.
 *
 *   CALLBACK_EVENT + WHDR_DONE polling loop (not waveOutClose alone):
 *     waveOutClose fails with WAVERR_STILLPLAYING while the buffer is in
 *     flight, and busy-Sleep(dur) would drift on a loaded system. The
 *     event wakes us when the driver finishes; the WHDR_DONE flag is the
 *     authoritative completion signal (the event also fires for WOM_OPEN,
 *     so waiting on the event alone is not enough). A dur+1s deadline
 *     guards against a driver that never signals (seen on broken virtual
 *     audio devices) — waveOutReset() then force-returns the buffer so
 *     unprepare/close cannot hang the polling thread forever.
 */

#include "tones.h"
#include "config.h"
#include "log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <mmsystem.h>   // WAVEFORMATEX / WAVEHDR / MMRESULT types and
                        // constants ONLY — we never link winmm.lib (see
                        // "SELF-PROXY SAFETY" in tones.h); every function
                        // goes through the GetProcAddress pointers below.

#include <cmath>
#include <vector>

namespace Tones {

namespace {

// ---------------------------------------------------------------------------
// waveOut function pointers, resolved from the REAL System32 winmm.dll.
// Signatures match mmsystem.h exactly (all winmm exports are WINAPI/stdcall).
// ---------------------------------------------------------------------------
typedef MMRESULT (WINAPI *waveOutOpen_t)(LPHWAVEOUT, UINT, LPCWAVEFORMATEX,
                                         DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *waveOutPrepareHeader_t)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *waveOutWrite_t)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *waveOutUnprepareHeader_t)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *waveOutReset_t)(HWAVEOUT);
typedef MMRESULT (WINAPI *waveOutClose_t)(HWAVEOUT);

waveOutOpen_t            p_waveOutOpen            = nullptr;
waveOutPrepareHeader_t   p_waveOutPrepareHeader   = nullptr;
waveOutWrite_t           p_waveOutWrite           = nullptr;
waveOutUnprepareHeader_t p_waveOutUnprepareHeader = nullptr;
waveOutReset_t           p_waveOutReset           = nullptr;
waveOutClose_t           p_waveOutClose           = nullptr;

// All six pointers resolved — the waveOut path is usable. Written once by
// Init() BEFORE any tone thread exists (see the call site in proxy.cpp's
// InitThread), read-only afterwards, so no synchronization is needed.
bool s_ready = false;

// One-shot log guard for runtime waveOut failures. A dead audio endpoint
// would otherwise log 3 lines/second from the wall thread alone; the first
// failure tells the whole story ("this session fell back to Beep").
// LONG + InterlockedExchange because several tone threads can hit the
// first failure simultaneously.
volatile LONG s_runtime_fail_logged = 0;

void LogRuntimeFailureOnce(const char* which, MMRESULT err)
{
    if (InterlockedExchange(&s_runtime_fail_logged, 1) == 0) {
        char msg[160];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "[FF7Access] Tone player: %s failed (err %u) — Beep() fallback "
            "for the rest of this session's failures.", which, err);
        Log::Write(msg);
    }
}

} // anonymous namespace

void Init()
{
    if (s_ready) return;   // idempotent

    // Load the real system winmm.dll by FULL absolute path. The absolute
    // path guarantees a distinct module-list entry even if a winmm-named
    // proxy (ours or another mod's) sits in the game folder — the same
    // technique winmm_proxy.cpp uses and documents. GetSystemDirectoryA
    // returns SysWOW64 for this 32-bit process, which is correct: we need
    // the 32-bit winmm.
    char sys_dir[MAX_PATH] = {};
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    char real_path[MAX_PATH] = {};
    _snprintf_s(real_path, MAX_PATH, _TRUNCATE, "%s\\winmm.dll", sys_dir);

    HMODULE winmm = LoadLibraryA(real_path);
    if (!winmm) {
        Log::Write("[FF7Access] Tone player: could not load system winmm.dll "
                   "— all tones fall back to Beep().");
        return;
    }

    p_waveOutOpen = reinterpret_cast<waveOutOpen_t>(
        GetProcAddress(winmm, "waveOutOpen"));
    p_waveOutPrepareHeader = reinterpret_cast<waveOutPrepareHeader_t>(
        GetProcAddress(winmm, "waveOutPrepareHeader"));
    p_waveOutWrite = reinterpret_cast<waveOutWrite_t>(
        GetProcAddress(winmm, "waveOutWrite"));
    p_waveOutUnprepareHeader = reinterpret_cast<waveOutUnprepareHeader_t>(
        GetProcAddress(winmm, "waveOutUnprepareHeader"));
    p_waveOutReset = reinterpret_cast<waveOutReset_t>(
        GetProcAddress(winmm, "waveOutReset"));
    p_waveOutClose = reinterpret_cast<waveOutClose_t>(
        GetProcAddress(winmm, "waveOutClose"));

    s_ready = p_waveOutOpen && p_waveOutPrepareHeader && p_waveOutWrite &&
              p_waveOutUnprepareHeader && p_waveOutReset && p_waveOutClose;

    if (s_ready) {
        Log::Write("[FF7Access] Tone player: waveOut ready (system winmm).");
    } else {
        // Never expected on a real Windows — these exports have existed
        // since Windows 3.1 — but the fallback keeps tones working anyway.
        Log::Write("[FF7Access] Tone player: waveOut exports missing "
                   "— all tones fall back to Beep().");
        FreeLibrary(winmm);   // nothing of it is in use; safe to release
    }
    // On success winmm stays pinned for the process lifetime — see the
    // no-Shutdown note in tones.h.
}

void Play(unsigned freq_hz, unsigned dur_ms)
{
    // tone_volume == 0 is the documented "all tones off" master switch —
    // deliberately checked BEFORE the fallback, so volume 0 also silences
    // the Beep() path.
    int vol = Config::Get().tone_volume;
    if (vol <= 0) return;
    if (vol > 100) vol = 100;   // Load() clamps too; belt and braces

    if (!s_ready) {
        Beep(freq_hz, dur_ms);  // pre-v2.30.41 behavior, unchanged
        return;
    }

    // ---- Synthesize: 16-bit mono sine at 44.1 kHz with 5 ms fades. -------
    constexpr unsigned kRate   = 44100;
    constexpr unsigned kFadeMs = 5;
    const size_t n_samples = static_cast<size_t>(kRate) * dur_ms / 1000;
    if (n_samples == 0) return;
    size_t fade = static_cast<size_t>(kRate) * kFadeMs / 1000;
    if (fade > n_samples / 2) fade = n_samples / 2;  // tiny tone: fades meet

    // Perceptual-ish volume curve — see the file header for why squared.
    const double amp = 32767.0 * (vol / 100.0) * (vol / 100.0);

    std::vector<int16_t> buf(n_samples);
    const double step = 2.0 * 3.14159265358979323846 * freq_hz / kRate;
    for (size_t i = 0; i < n_samples; ++i) {
        double env = 1.0;
        if (i < fade)                  env = static_cast<double>(i) / fade;
        else if (i >= n_samples - fade) env = static_cast<double>(n_samples - 1 - i) / fade;
        buf[i] = static_cast<int16_t>(amp * env * sin(step * i));
    }

    // ---- Play through the default device, blocking until done. -----------
    WAVEFORMATEX fmt = {};
    fmt.wFormatTag      = WAVE_FORMAT_PCM;
    fmt.nChannels       = 1;
    fmt.nSamplesPerSec  = kRate;
    fmt.wBitsPerSample  = 16;
    fmt.nBlockAlign     = static_cast<WORD>(fmt.nChannels * fmt.wBitsPerSample / 8);
    fmt.nAvgBytesPerSec = fmt.nSamplesPerSec * fmt.nBlockAlign;

    // Manual-reset is NOT wanted here: the driver signals the event for
    // WOM_OPEN, WOM_DONE and WOM_CLOSE alike, and the loop below re-waits
    // after each wake until the authoritative WHDR_DONE flag appears — an
    // auto-reset event makes each wake consume exactly one signal.
    HANDLE done_event = CreateEventA(nullptr, /*bManualReset=*/FALSE,
                                     /*bInitialState=*/FALSE, nullptr);
    if (!done_event) {
        Beep(freq_hz, dur_ms);
        return;
    }

    HWAVEOUT hwo = nullptr;
    MMRESULT mr = p_waveOutOpen(&hwo, WAVE_MAPPER, &fmt,
                                reinterpret_cast<DWORD_PTR>(done_event), 0,
                                CALLBACK_EVENT);
    if (mr != MMSYSERR_NOERROR) {
        // No usable render endpoint (or exclusive-mode lockout). Beep()
        // may still reach something (and is what pre-v2.30.41 builds did).
        LogRuntimeFailureOnce("waveOutOpen", mr);
        CloseHandle(done_event);
        Beep(freq_hz, dur_ms);
        return;
    }

    WAVEHDR hdr = {};
    hdr.lpData         = reinterpret_cast<LPSTR>(buf.data());
    hdr.dwBufferLength = static_cast<DWORD>(buf.size() * sizeof(int16_t));

    mr = p_waveOutPrepareHeader(hwo, &hdr, sizeof(hdr));
    if (mr != MMSYSERR_NOERROR) {
        LogRuntimeFailureOnce("waveOutPrepareHeader", mr);
        p_waveOutClose(hwo);
        CloseHandle(done_event);
        Beep(freq_hz, dur_ms);
        return;
    }

    mr = p_waveOutWrite(hwo, &hdr, sizeof(hdr));
    if (mr != MMSYSERR_NOERROR) {
        LogRuntimeFailureOnce("waveOutWrite", mr);
        p_waveOutUnprepareHeader(hwo, &hdr, sizeof(hdr));
        p_waveOutClose(hwo);
        CloseHandle(done_event);
        Beep(freq_hz, dur_ms);
        return;
    }

    // Block until the driver marks the buffer done — this is what preserves
    // Beep()'s blocking contract for the call sites. The deadline handles a
    // driver that never signals: waveOutReset() force-completes the buffer
    // (WHDR_DONE gets set) so the unprepare/close below can't hang.
    const DWORD deadline = GetTickCount() + dur_ms + 1000;
    while (!(hdr.dwFlags & WHDR_DONE)) {
        if (static_cast<int32_t>(deadline - GetTickCount()) <= 0) {
            p_waveOutReset(hwo);
            break;
        }
        WaitForSingleObject(done_event, 50);
    }

    p_waveOutUnprepareHeader(hwo, &hdr, sizeof(hdr));
    p_waveOutClose(hwo);
    CloseHandle(done_event);
}

} // namespace Tones
