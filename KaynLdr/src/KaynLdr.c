/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 */

#include <KaynLdr.h>
#include <Win32.h>
#include <Macros.h>

DLLEXPORT VOID KaynLoader( LPVOID lpParameter )
{
    INSTANCE                Instance        = { 0 };
    HMODULE                 KaynLibraryLdr  = NULL;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    LPVOID                  KVirtualMemory  = NULL;
    DWORD                   KMemSize        = 0;
    PVOID                   SecMemory       = NULL;
    PVOID                   SecMemorySize   = 0;
    PVOID                   RawDataPtr      = 0;
    DWORD                   Protection      = 0;
    ULONG                   OldProtection   = 0;
    LPVOID                  pImageDir       = NULL;

    // 0. First we need to get our own image base
    KaynLibraryLdr = KaynCaller();

    // ------------------------
    // 1. Load needed Functions
    // ------------------------
    Instance.Modules.Ntdll                 = KGetModuleByHash( NTDLL_HASH );

    Instance.Win32.LdrLoadDll              = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_LDRLOADDLL, 0  );
    Instance.Win32.NtAllocateVirtualMemory = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY, 0 );
    Instance.Win32.NtProtectVirtualMemory  = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY, 0 );

    // ---------------------------------------------------------------------------
    // 2. Allocate virtual memory and copy headers and section into the new memory
    // ---------------------------------------------------------------------------
    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage;

    if ( NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        // ---- Copy Headers into new allocated memory ----
        MemCopy( KVirtualMemory, KaynLibraryLdr, NtHeaders->OptionalHeader.SizeOfHeaders );

        // ---- Copy Sections into new allocated memory ----
        SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress );
            RawDataPtr      = C_PTR( KaynLibraryLdr + SecHeader[ i ].PointerToRawData );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READ;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;

            MemCopy( SecMemory, RawDataPtr, SecMemorySize );

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        // ----------------------------------
        // 3. Process our images import table
        // ----------------------------------
        NtHeaders = C_PTR( KVirtualMemory + ( ( PIMAGE_DOS_HEADER ) KVirtualMemory )->e_lfanew );
        pImageDir = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

        KResolveIAT( &Instance, KVirtualMemory, pImageDir );

        // ----------------------------------------
        // 4. Process all of our images relocations
        // ----------------------------------------
        KReAllocSections(
                KVirtualMemory,
                NtHeaders->OptionalHeader.ImageBase,
                C_PTR( KVirtualMemory + ( ( PIMAGE_DATA_DIRECTORY ) pImageDir )->VirtualAddress )
        );

        // --------------------------------
        // 5. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, lpParameter );
    }
}