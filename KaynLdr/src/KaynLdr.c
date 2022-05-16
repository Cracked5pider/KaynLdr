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
    DWORD                   Protection      = 0;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir       = NULL;

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
        // ---- Copy Sections into new allocated memory ----
        SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            MemCopy(
                C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress ),    // Section New Memory
                C_PTR( KaynLibraryLdr + SecHeader[ i ].PointerToRawData ),  // Section Raw Data
                SecHeader[ i ].SizeOfRawData                                // Section Size
            );
        }

        // ----------------------------------
        // 3. Process our images import table
        // ----------------------------------
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        if ( ImageDir->VirtualAddress )
            KResolveIAT( &Instance, KVirtualMemory, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ) );

        // ----------------------------
        // 4. Process image relocations
        // ----------------------------
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImageDir->VirtualAddress )
            KReAllocSections( KVirtualMemory, NtHeaders->OptionalHeader.ImageBase, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ) );

        // ----------------------------------
        // 5. Set protection for each section
        // ----------------------------------
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress );
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

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        // --------------------------------
        // 6. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, lpParameter );
    }
}