/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 * Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
 */

#ifndef KAYNLDR_SYSCALL_H
#define KAYNLDR_SYSCALL_H

#include <Win32.h>

#define UP   -32
#define DOWN 32

VOID     SyscallPrepare( DWORD );
NTSTATUS SyscallInvoke( );

WORD     GetSyscall( PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD FunctionSysHash );
#endif
