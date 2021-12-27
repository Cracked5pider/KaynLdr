/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 * Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
 */

#ifndef KAYNLDR_WIN32_H
#define KAYNLDR_WIN32_H

#include <windows.h>
#include <winternl.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#define HASH_KEY 5381

#ifdef WIN_X64
    #define PPEB_PTR __readgsqword( 0x60 )
#else
    #define PPEB_PTR __readgsqword( 0x30 )
#endif

#define NtGetCurrentProcess()           (HANDLE) ( (HANDLE)   - 1 )

#define RVA_2_VA(T, B, R)               (T)( (PBYTE) B + R )

#define KERNEL32_HASH                   0xadd31df0
#define NTDLL_HASH                      0x70e61753

#define SYS_NTALLOCATEVIRTUALMEMORY     0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x50e92888

#define WIN32_LOADLIBRARYA              0xb7072fdb

#define DLLEXPORT                       __declspec(dllexport)
#define API_DEFINE( x, n )              __typeof__( x ) *n

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

DWORD   KHashString( LPVOID String, SIZE_T Size );
SIZE_T  KStringLengthA( LPCSTR String );
VOID    KMemSet( PVOID Destination, INT Value, SIZE_T Size );

HMODULE KGetModuleByHash( DWORD hash );
FARPROC KGetProcAddressByHash( HMODULE DllModuleBase, DWORD FunctionHash, DWORD Ordinal );

VOID    KResolveIAT( LPVOID KaynImage, LPVOID IatDir );
VOID    KReAllocSections( LPVOID KaynImage, ULONGLONG ImageBase, UINT_PTR Dir );

#endif
