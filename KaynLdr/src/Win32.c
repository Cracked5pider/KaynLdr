/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 * Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
 */

#include <Win32.h>

HMODULE KGetModuleByHash( DWORD hash )
{
    PLDR_DATA_TABLE_ENTRY pModule       = (PLDR_DATA_TABLE_ENTRY)((PPEB) PPEB_PTR)->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pFirstModule  = pModule;
#ifdef DEBUG
    printf("pModule: %x\n", pModule);
#endif
    do
    {
        DWORD ModuleHash = KHashString( (WCHAR*)pModule->FullDllName.Buffer, pModule->FullDllName.Length );

        if (ModuleHash == hash)
            return (HMODULE)pModule->Reserved2[0];
        else
            pModule = (PLDR_DATA_TABLE_ENTRY)pModule->Reserved1[0];

    } while ( pModule && pModule != pFirstModule );

    return INVALID_HANDLE_VALUE;
}

FARPROC KGetProcAddressByHash( HMODULE DllModuleBase, DWORD FunctionHash, DWORD Ordinal )
{
    PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
    PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
    PDWORD                  AddressOfFunctions      = NULL;
    PDWORD                  AddressOfNames          = NULL;
    PWORD                   AddressOfNameOrdinals   = NULL;

    ModuleNtHeader          = RVA_2_VA(PIMAGE_NT_HEADERS, DllModuleBase, ((PIMAGE_DOS_HEADER) DllModuleBase)->e_lfanew);
    ModuleExportedDirectory = RVA_2_VA(PIMAGE_EXPORT_DIRECTORY, DllModuleBase, ModuleNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    AddressOfNames          = RVA_2_VA(PDWORD, DllModuleBase, ModuleExportedDirectory->AddressOfNames);
    AddressOfFunctions      = RVA_2_VA(PDWORD, DllModuleBase, ModuleExportedDirectory->AddressOfFunctions);
    AddressOfNameOrdinals   = RVA_2_VA(PWORD,  DllModuleBase, ModuleExportedDirectory->AddressOfNameOrdinals);

    if ( (Ordinal != 0) && (((DWORD_PTR)Ordinal >> 16) == 0) )
    {
        WORD  ordinal = Ordinal & 0xFFFF;
        if (ordinal < ModuleExportedDirectory->Base || ordinal >= ModuleExportedDirectory->Base + ModuleExportedDirectory->NumberOfFunctions)
            return NULL;
        return RVA_2_VA( FARPROC, DllModuleBase, AddressOfFunctions[AddressOfNameOrdinals[ordinal - ModuleExportedDirectory->Base]] );
    }

    for (DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++)
    {
        if ( KHashString( (PCHAR)DllModuleBase + AddressOfNames[i], KStringLengthA((PCHAR)DllModuleBase + AddressOfNames[i]) ) == FunctionHash )
            return RVA_2_VA( FARPROC, DllModuleBase, AddressOfFunctions[AddressOfNameOrdinals[i]] );
    }

    return NULL;
}

VOID KResolveIAT( LPVOID KaynImage, LPVOID IatDir )
{
    API_DEFINE( LoadLibraryA , Win32_LoadLibraryA );

    PIMAGE_THUNK_DATA        OriginalTD        = NULL;
    PIMAGE_THUNK_DATA        FirstTD           = NULL;

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME    pImportByName     = NULL;

    PCHAR                    ImportModuleName  = NULL;
    HMODULE                  ImportModule      = NULL;

    Win32_LoadLibraryA       = KGetProcAddressByHash( KGetModuleByHash( KERNEL32_HASH ), WIN32_LOADLIBRARYA, 0 );

    for ( pImportDescriptor = IatDir; pImportDescriptor->Name != 0; ++pImportDescriptor )
    {
        ImportModuleName = RVA_2_VA( PCHAR, KaynImage, pImportDescriptor->Name );
        ImportModule = Win32_LoadLibraryA( ImportModuleName );

        OriginalTD  = RVA_2_VA( PIMAGE_THUNK_DATA, KaynImage, pImportDescriptor->OriginalFirstThunk );
        FirstTD     = RVA_2_VA( PIMAGE_THUNK_DATA, KaynImage, pImportDescriptor->FirstThunk );

        for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
            {
                LPVOID Function = KGetProcAddressByHash( ImportModule, NULL, IMAGE_ORDINAL(OriginalTD->u1.Ordinal) );
                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
            else
            {
                pImportByName       = RVA_2_VA( PIMAGE_IMPORT_BY_NAME, KaynImage, OriginalTD->u1.AddressOfData );
                DWORD  FunctionHash = KHashString( pImportByName->Name, KStringLengthA(pImportByName->Name) );
                LPVOID Function     = KGetProcAddressByHash( ImportModule, FunctionHash, 0 );

                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
        }
    }
}

VOID KReAllocSections( LPVOID KaynImage, ULONGLONG ImageBase, UINT_PTR BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = (LPVOID)BaseRelocDir;
    PIMAGE_RELOC            pImageR  = NULL;

    LPVOID                  OffsetIB = (LPVOID)((UINT_PTR)KaynImage - ImageBase);

    /* Is a relocation! */
    while ( pImageBR->VirtualAddress != 0 )
    {
        pImageR = (PIMAGE_RELOC) ( pImageBR + 1 );

        /* Exceed the size of the relocation? */
        while ( pImageR != ( (UINT_PTR)pImageBR  + (UINT_PTR)pImageBR->SizeOfBlock )  )
        {
            UINT_PTR Rel = (UINT_PTR)KaynImage + (UINT_PTR)pImageBR->VirtualAddress + (UINT_PTR)pImageR->offset;
            switch( pImageR->type )
            {
                case IMAGE_REL_BASED_DIR64:
                    *(PDWORD64)( Rel ) += (DWORD64)OffsetIB;
                    break;

                case IMAGE_REL_BASED_HIGHLOW:
                    *(PDWORD32)( Rel ) += (DWORD32)OffsetIB;
                    break;
            }
            ++pImageBR;
        };
        pImageBR = (PIMAGE_BASE_RELOCATION)pImageR;
    }
}

/*
 ---------------------------------
 ---- String & Data functions ----
 ---------------------------------
*/

// Inspired Hashing algo from TitanLdr by SecIdiot (https://github.com/SecIdiot/TitanLdr)
DWORD KHashString( PVOID String, SIZE_T Length )
{
    ULONG	Hash = HASH_KEY;
    PUCHAR	Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

VOID KMemSet(PVOID Destination, INT Value, SIZE_T Size)
{
    PBYTE D = (PBYTE)Destination;

    while (Size--) *D++ = Value;

    return;
}