/*
 * winmm_proxy.cpp -- winmm.dll proxy: runtime stubs + timeGetTime init trigger.
 *
 * WHY RUNTIME STUBS (not .def forwarding):
 *   .def forwarding syntax "funcname = WINMM.funcname" requires:
 *     1. winmm.lib linked, so the linker can verify the forward target exists.
 *     2. At runtime, Windows resolves "WINMM" to find the forwarding target.
 *   Problem: our DLL IS named "winmm.dll". When the OS resolves "WINMM" it finds
 *   US (the proxy), creating an infinite forwarding loop. No amount of Known-DLL
 *   path tricks avoids this because the module-list name collision happens first.
 *
 *   The correct approach is runtime stubs: load the REAL system winmm.dll from
 *   System32 (using its full absolute path, which gives it a different module-
 *   list entry than our copy in the FF7 folder), resolve each function pointer
 *   via GetProcAddress, and implement each stub as a naked JMP through that pointer.
 *
 * STUB MECHANISM (x86 __stdcall and __cdecl):
 *   All winmm functions are __stdcall (callee cleans the stack with RET N).
 *   A naked JMP to the real function passes control with the exact same stack
 *   layout as a direct call: the real function pops its own parameters with
 *   RET N and returns directly to our caller. No prologue/epilogue is needed.
 *
 *   MSVC x86 inline asm:
 *     __declspec(naked) void FuncName() { __asm { jmp [fp_FuncName] } }
 *   generates: FF 25 [&fp_FuncName]  (indirect JMP through memory)
 *
 * INIT TRIGGER:
 *   timeGetTime() is called every game frame and is implemented by us (not a stub).
 *   We use it to trigger Config::Load, TTS::Init, and Hooks::Install once the
 *   game has finished initializing. See the design rationale in winmm_proxy.h.
 *
 * X-MACRO PATTERN:
 *   WINMM_FORWARD_FUNCS(X) expands X(name) for each forwarded function.
 *   Three passes over this macro generate:
 *     1. void* fp_name = nullptr;          (function pointer variables)
 *     2. naked stub bodies                 (one per function)
 *     3. fp_name = GetProcAddress(...)     (resolver calls in Init())
 */

#include "winmm_proxy.h"
#include "hooks.h"
#include "tts.h"
#include "config.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// ---------------------------------------------------------------------------
// Complete list of winmm exports we stub, derived from:
//   dumpbin /exports C:\Windows\SysWOW64\winmm.dll
// Excludes: timeGetTime (implemented by us), "functions"/"names" (data table entries).
// ---------------------------------------------------------------------------
#define WINMM_FORWARD_FUNCS(X) \
    X(aux32Message) \
    X(auxGetDevCapsA) \
    X(auxGetDevCapsW) \
    X(auxGetNumDevs) \
    X(auxGetVolume) \
    X(auxOutMessage) \
    X(auxSetVolume) \
    X(CloseDriver) \
    X(DefDriverProc) \
    X(DriverCallback) \
    X(DrvGetModuleHandle) \
    X(GetDriverModuleHandle) \
    X(joy32Message) \
    X(joyConfigChanged) \
    X(joyGetDevCapsA) \
    X(joyGetDevCapsW) \
    X(joyGetNumDevs) \
    X(joyGetPos) \
    X(joyGetPosEx) \
    X(joyGetThreshold) \
    X(joyReleaseCapture) \
    X(joySetCapture) \
    X(joySetThreshold) \
    X(mci32Message) \
    X(mciDriverNotify) \
    X(mciDriverYield) \
    X(mciExecute) \
    X(mciFreeCommandResource) \
    X(mciGetCreatorTask) \
    X(mciGetDeviceIDA) \
    X(mciGetDeviceIDFromElementIDA) \
    X(mciGetDeviceIDFromElementIDW) \
    X(mciGetDeviceIDW) \
    X(mciGetDriverData) \
    X(mciGetErrorStringA) \
    X(mciGetErrorStringW) \
    X(mciGetYieldProc) \
    X(mciLoadCommandResource) \
    X(mciSendCommandA) \
    X(mciSendCommandW) \
    X(mciSendStringA) \
    X(mciSendStringW) \
    X(mciSetDriverData) \
    X(mciSetYieldProc) \
    X(mid32Message) \
    X(midiConnect) \
    X(midiDisconnect) \
    X(midiInAddBuffer) \
    X(midiInClose) \
    X(midiInGetDevCapsA) \
    X(midiInGetDevCapsW) \
    X(midiInGetErrorTextA) \
    X(midiInGetErrorTextW) \
    X(midiInGetID) \
    X(midiInGetNumDevs) \
    X(midiInMessage) \
    X(midiInOpen) \
    X(midiInPrepareHeader) \
    X(midiInReset) \
    X(midiInStart) \
    X(midiInStop) \
    X(midiInUnprepareHeader) \
    X(midiOutCacheDrumPatches) \
    X(midiOutCachePatches) \
    X(midiOutClose) \
    X(midiOutGetDevCapsA) \
    X(midiOutGetDevCapsW) \
    X(midiOutGetErrorTextA) \
    X(midiOutGetErrorTextW) \
    X(midiOutGetID) \
    X(midiOutGetNumDevs) \
    X(midiOutGetVolume) \
    X(midiOutLongMsg) \
    X(midiOutMessage) \
    X(midiOutOpen) \
    X(midiOutPrepareHeader) \
    X(midiOutReset) \
    X(midiOutSetVolume) \
    X(midiOutShortMsg) \
    X(midiOutUnprepareHeader) \
    X(midiStreamClose) \
    X(midiStreamOpen) \
    X(midiStreamOut) \
    X(midiStreamPause) \
    X(midiStreamPosition) \
    X(midiStreamProperty) \
    X(midiStreamRestart) \
    X(midiStreamStop) \
    X(mixerClose) \
    X(mixerGetControlDetailsA) \
    X(mixerGetControlDetailsW) \
    X(mixerGetDevCapsA) \
    X(mixerGetDevCapsW) \
    X(mixerGetID) \
    X(mixerGetLineControlsA) \
    X(mixerGetLineControlsW) \
    X(mixerGetLineInfoA) \
    X(mixerGetLineInfoW) \
    X(mixerGetNumDevs) \
    X(mixerMessage) \
    X(mixerOpen) \
    X(mixerSetControlDetails) \
    X(mmDrvInstall) \
    X(mmGetCurrentTask) \
    X(mmioAdvance) \
    X(mmioAscend) \
    X(mmioClose) \
    X(mmioCreateChunk) \
    X(mmioDescend) \
    X(mmioFlush) \
    X(mmioGetInfo) \
    X(mmioInstallIOProcA) \
    X(mmioInstallIOProcW) \
    X(mmioOpenA) \
    X(mmioOpenW) \
    X(mmioRead) \
    X(mmioRenameA) \
    X(mmioRenameW) \
    X(mmioSeek) \
    X(mmioSendMessage) \
    X(mmioSetBuffer) \
    X(mmioSetInfo) \
    X(mmioStringToFOURCCA) \
    X(mmioStringToFOURCCW) \
    X(mmioWrite) \
    X(mmsystemGetVersion) \
    X(mmTaskBlock) \
    X(mmTaskCreate) \
    X(mmTaskSignal) \
    X(mmTaskYield) \
    X(mod32Message) \
    X(mxd32Message) \
    X(NotifyCallbackData) \
    X(OpenDriver) \
    X(PlaySound) \
    X(PlaySoundA) \
    X(PlaySoundW) \
    X(SendDriverMessage) \
    X(sndPlaySoundA) \
    X(sndPlaySoundW) \
    X(tid32Message) \
    X(timeBeginPeriod) \
    X(timeEndPeriod) \
    X(timeGetDevCaps) \
    X(timeGetSystemTime) \
    X(timeKillEvent) \
    X(timeSetEvent) \
    X(waveInAddBuffer) \
    X(waveInClose) \
    X(waveInGetDevCapsA) \
    X(waveInGetDevCapsW) \
    X(waveInGetErrorTextA) \
    X(waveInGetErrorTextW) \
    X(waveInGetID) \
    X(waveInGetNumDevs) \
    X(waveInGetPosition) \
    X(waveInMessage) \
    X(waveInOpen) \
    X(waveInPrepareHeader) \
    X(waveInReset) \
    X(waveInStart) \
    X(waveInStop) \
    X(waveInUnprepareHeader) \
    X(waveOutBreakLoop) \
    X(waveOutClose) \
    X(waveOutGetDevCapsA) \
    X(waveOutGetDevCapsW) \
    X(waveOutGetErrorTextA) \
    X(waveOutGetErrorTextW) \
    X(waveOutGetID) \
    X(waveOutGetNumDevs) \
    X(waveOutGetPitch) \
    X(waveOutGetPlaybackRate) \
    X(waveOutGetPosition) \
    X(waveOutGetVolume) \
    X(waveOutMessage) \
    X(waveOutOpen) \
    X(waveOutPause) \
    X(waveOutPrepareHeader) \
    X(waveOutReset) \
    X(waveOutRestart) \
    X(waveOutSetPitch) \
    X(waveOutSetPlaybackRate) \
    X(waveOutSetVolume) \
    X(waveOutUnprepareHeader) \
    X(waveOutWrite) \
    X(wid32Message) \
    X(wod32Message) \
    X(WOW32DriverCallback) \
    X(WOW32ResolveMultiMediaHandle) \
    X(WOWAppExit)

// ---------------------------------------------------------------------------
// Pass 1: Declare one void* function pointer variable per forwarded function.
// All start as nullptr; populated by WinmmProxy::Init().
// ---------------------------------------------------------------------------
#define DECLARE_FP(name) static void* fp_##name = nullptr;
WINMM_FORWARD_FUNCS(DECLARE_FP)
#undef DECLARE_FP

// ---------------------------------------------------------------------------
// Pass 2: Naked stub functions — one per forwarded function.
//
// Each stub is a single indirect JMP through the corresponding fp_* variable.
// The JMP passes control to the real system function with the EXACT same stack
// frame as if the caller had called it directly. This works for both __stdcall
// (where the callee cleans the stack with RET N) and __cdecl (caller cleans).
//
// Generates: FF 25 [&fp_name]  (JMP DWORD PTR [abs_addr])
// ---------------------------------------------------------------------------
#define MAKE_STUB(name) \
    extern "C" void __declspec(naked) name() { __asm { jmp [fp_##name] } }
WINMM_FORWARD_FUNCS(MAKE_STUB)
#undef MAKE_STUB

// ---------------------------------------------------------------------------
// timeGetTime state and implementation
// ---------------------------------------------------------------------------

namespace WinmmProxy {

// Handle to the real system winmm.dll, loaded from System32 in Init().
static HMODULE s_real_winmm      = nullptr;
static bool    s_winmm_loaded    = false;
static bool    s_mod_initialized = false;
static bool    s_hooks_installed = false;

// Real timeGetTime pointer — used to delegate after hook installation.
static DWORD (WINAPI* s_real_timeGetTime)() = nullptr;

void Init()
{
    if (s_winmm_loaded) return;
    s_winmm_loaded = true;

    // Load the real system winmm.dll from System32 by its FULL absolute path.
    // Using the full path creates a distinct module-list entry from our proxy
    // (which lives in the FF7 folder). They coexist because the canonical paths differ.
    char sys_dir[MAX_PATH] = {};
    GetSystemDirectoryA(sys_dir, MAX_PATH);

    char real_path[MAX_PATH] = {};
    _snprintf_s(real_path, MAX_PATH, _TRUNCATE, "%s\\winmm.dll", sys_dir);

    s_real_winmm = LoadLibraryA(real_path);
    if (!s_real_winmm) {
        OutputDebugStringA("[FF7Access] FATAL: could not load system winmm.dll.\n");
        return;
    }

    // Pass 3: Resolve all stub function pointers from the real system winmm.
#define RESOLVE_FP(name) fp_##name = GetProcAddress(s_real_winmm, #name);
    WINMM_FORWARD_FUNCS(RESOLVE_FP)
#undef RESOLVE_FP

    // Also resolve the real timeGetTime for our delegation.
    s_real_timeGetTime = reinterpret_cast<DWORD(WINAPI*)()>(
        GetProcAddress(s_real_winmm, "timeGetTime"));

    if (!s_real_timeGetTime) {
        OutputDebugStringA("[FF7Access] Warning: real timeGetTime not found, "
                           "falling back to GetTickCount.\n");
    }
}

void Shutdown()
{
    if (s_real_winmm) {
        FreeLibrary(s_real_winmm);
        s_real_winmm       = nullptr;
        s_real_timeGetTime = nullptr;
    }
}

} // namespace WinmmProxy

// ---------------------------------------------------------------------------
// timeGetTime — our only non-stub exported function.
//
// Doubles as the hook installation trigger: every game frame calls this,
// so we use it to fire Config::Load, TTS::Init, and Hooks::Install once
// the field module has populated the opcode table (Hooks::Install returns
// false until then).
// ---------------------------------------------------------------------------
extern "C" DWORD WINAPI timeGetTime()
{
    if (!WinmmProxy::s_hooks_installed) {
        if (!WinmmProxy::s_mod_initialized) {
            Config::Load();
            TTS::Init();
            WinmmProxy::s_mod_initialized = true;
        }
        if (Hooks::Install()) {
            WinmmProxy::s_hooks_installed = true;
        }
    }

    return WinmmProxy::s_real_timeGetTime
        ? WinmmProxy::s_real_timeGetTime()
        : GetTickCount();
}
