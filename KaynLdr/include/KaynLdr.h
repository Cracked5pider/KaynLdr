/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 */

#ifndef KAYNLDR_KAYNLDR_H
#define KAYNLDR_KAYNLDR_H

#include <windows.h>
#include <Native.h>
#include <Macros.h>

#define DLL_QUERY_HMODULE   6

typedef struct {

    struct {
        WIN32_FUNC( LdrLoadDll );
        WIN32_FUNC( NtAllocateVirtualMemory )
        WIN32_FUNC( NtProtectVirtualMemory )
    } Win32;

    struct {
        PVOID   Ntdll;
    } Modules ;

} INSTANCE, *PINSTANCE ;

LPVOID  KaynCaller();

#endif
