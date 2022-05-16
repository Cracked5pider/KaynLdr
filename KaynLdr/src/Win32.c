/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 * Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
 */

#include <Win32.h>
#include <Macros.h>
#include <KaynLdr.h>


#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

PVOID KGetModuleByHash( DWORD ModuleHash )
{
    PLDR_DATA_TABLE_ENTRY   LoaderEntry = NULL;
    PLIST_ENTRY             ModuleList  = NULL;
    PLIST_ENTRY             NextList    = NULL;

    /* Get pointer to list */
    ModuleList = & ( ( PPEB ) PPEB_PTR )->Ldr->InLoadOrderModuleList;
    NextList   = ModuleList->Flink;

    for ( ; ModuleList != NextList ; NextList = NextList->Flink )
    {
        LoaderEntry = NextList;

        if ( KHashString( LoaderEntry->BaseDllName.Buffer, LoaderEntry->BaseDllName.Length ) == ModuleHash )
            return LoaderEntry->DllBase;
    }

    return NULL;
}

__forceinline UINT32 CopyDotStr( PCHAR String )
{
    for ( UINT32 i = 0; i < KStringLengthA( String ); i++ )
    {
        if ( String[ i ] == '.' )
            return i;
    }
}

PVOID KGetProcAddressByHash( PINSTANCE Instance, PVOID DllModuleBase, DWORD FunctionHash, DWORD Ordinal )
{
    PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
    PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
    SIZE_T                  ExportedDirectorySize   = 0;
    PDWORD                  AddressOfFunctions      = NULL;
    PDWORD                  AddressOfNames          = NULL;
    PWORD                   AddressOfNameOrdinals   = NULL;
    PVOID                   FunctionAddr            = NULL;
    UINT32                  Index                   = 0;

    ModuleNtHeader          = C_PTR( DllModuleBase + ( ( PIMAGE_DOS_HEADER ) DllModuleBase )->e_lfanew );
    ModuleExportedDirectory = C_PTR( DllModuleBase + ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExportedDirectorySize   = C_PTR( DllModuleBase + ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddressOfNames          = C_PTR( DllModuleBase + ModuleExportedDirectory->AddressOfNames );
    AddressOfFunctions      = C_PTR( DllModuleBase + ModuleExportedDirectory->AddressOfFunctions );
    AddressOfNameOrdinals   = C_PTR( DllModuleBase + ModuleExportedDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++ )
    {
        if ( KHashString( C_PTR( ( PCHAR ) DllModuleBase + AddressOfNames[ i ] ), 0 ) == FunctionHash )
        {
            FunctionAddr = C_PTR( DllModuleBase + AddressOfFunctions[ AddressOfNameOrdinals[ i ] ] );
            if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ModuleExportedDirectory &&
                 ( ULONG_PTR ) FunctionAddr <  ( ULONG_PTR ) ModuleExportedDirectory + ExportedDirectorySize )
            {
                CHAR    Library [ MAX_PATH ] = { 0 };
                CHAR    Function[ MAX_PATH ] = { 0 };

                // where is the dot
                Index = CopyDotStr( FunctionAddr );

                // Copy the library from our string
                MemCopy( Library,  FunctionAddr, Index );

                // Copy the function from our string
                MemCopy( Function, C_PTR( FunctionAddr + Index + 1 ), KStringLengthA( C_PTR( FunctionAddr + Index + 1 ) ) );

                DllModuleBase = KLoadLibrary( Instance, Library );
                FunctionAddr  = KGetProcAddressByHash( Instance, DllModuleBase, KHashString( Function, 0 ), 0 );
            }

            return FunctionAddr;
        }
    }

    return NULL;
}

VOID KResolveIAT( PINSTANCE Instance, LPVOID KaynImage, LPVOID IatDir )
{
    PIMAGE_THUNK_DATA        OriginalTD        = NULL;
    PIMAGE_THUNK_DATA        FirstTD           = NULL;

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME    pImportByName     = NULL;

    PCHAR                    ImportModuleName  = NULL;
    HMODULE                  ImportModule      = NULL;

    for ( pImportDescriptor = IatDir; pImportDescriptor->Name != 0; ++pImportDescriptor )
    {
        ImportModuleName = C_PTR( KaynImage + pImportDescriptor->Name );
        ImportModule     = KLoadLibrary( Instance, ImportModuleName );

        OriginalTD       = C_PTR( KaynImage + pImportDescriptor->OriginalFirstThunk );
        FirstTD          = C_PTR( KaynImage + pImportDescriptor->FirstThunk );

        for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
            {
                // TODO: get function by ordinal
                PVOID Function = KGetProcAddressByHash( Instance, ImportModule, NULL, IMAGE_ORDINAL( OriginalTD->u1.Ordinal ) );
                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
            else
            {
                pImportByName       = C_PTR( KaynImage + OriginalTD->u1.AddressOfData );
                DWORD  FunctionHash = KHashString( pImportByName->Name, KStringLengthA( pImportByName->Name ) );
                LPVOID Function     = KGetProcAddressByHash( Instance, ImportModule, FunctionHash, 0 );

                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
        }
    }
}

VOID KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = C_PTR( BaseRelocDir );
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

PVOID KLoadLibrary( PINSTANCE Instance, LPSTR ModuleName )
{
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = KStringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    KCharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize             = KStringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;
}

/*
 ---------------------------------
 ---- String & Data functions ----
 ---------------------------------
*/

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

SIZE_T KStringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}