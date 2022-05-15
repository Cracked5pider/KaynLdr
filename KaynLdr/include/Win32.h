/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 */

#ifndef KAYNLDR_WIN32_H
#define KAYNLDR_WIN32_H

#include <KaynLdr.h>

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

PVOID   KGetModuleByHash( DWORD hash );
PVOID   KGetProcAddressByHash( PINSTANCE Instance, PVOID DllModuleBase, DWORD FunctionHash, DWORD Ordinal );
PVOID   KLoadLibrary( PINSTANCE Instance, LPSTR Module );

VOID    KResolveIAT( PINSTANCE Instance, PVOID KaynImage, PVOID IatDir );
VOID    KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID Dir );

DWORD   KHashString( LPVOID String, SIZE_T Size );
SIZE_T  KStringLengthA( LPCSTR String );
SIZE_T  KStringLengthW( LPCWSTR String );
VOID    KMemSet( PVOID Destination, INT Value, SIZE_T Size );
SIZE_T  KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );

#endif
