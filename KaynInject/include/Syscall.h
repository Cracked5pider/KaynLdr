#ifndef KAYNINJECT_SYSCALL_H
#define KAYNINJECT_SYSCALL_H

#include <windows.h>

// Get syscall ID
WORD     GetSyscall( LPVOID, PIMAGE_EXPORT_DIRECTORY, DWORD );

// Prepare and invoke syscall
VOID     SyscallPrepare( WORD );
NTSTATUS SyscallInvoke();

#endif
