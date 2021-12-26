#include <Syscall.h>
#include <KaynInject.h>
#include <stdio.h>

extern VOID     SyscallPrepare( WORD );
extern NTSTATUS SyscallInvoke();

#define UP   -32
#define DOWN 32

WORD GetSyscall( PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD FunctionSysHash )
{
    PDWORD  AddressOfFunctions    = RVA_2_VA( PDWORD, pModuleBase, pImageExportDirectory->AddressOfFunctions );
    PDWORD  AddressOfNames        = RVA_2_VA( PDWORD, pModuleBase, pImageExportDirectory->AddressOfNames );
    PWORD   AddressOfNameOrdinals = RVA_2_VA( PWORD, pModuleBase, pImageExportDirectory->AddressOfNameOrdinals );

    WORD    wSystemCall = -1;

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++)
    {
        PCHAR pczFunctionName  = RVA_2_VA( PCHAR, pModuleBase, AddressOfNames[cx] );
        PVOID pFunctionAddress = (PBYTE)pModuleBase + AddressOfFunctions[AddressOfNameOrdinals[cx]];

        if ( HashStringA(pczFunctionName) == FunctionSysHash )
        {
            if (*((PBYTE)pFunctionAddress) == 0x4c
                && *((PBYTE)pFunctionAddress + 1) == 0x8b
                && *((PBYTE)pFunctionAddress + 2) == 0xd1
                && *((PBYTE)pFunctionAddress + 3) == 0xb8
                && *((PBYTE)pFunctionAddress + 6) == 0x00
                && *((PBYTE)pFunctionAddress + 7) == 0x00)
            {
                __builtin_memcpy(&wSystemCall, (pFunctionAddress + 4), 2);
                return wSystemCall;
            }

            if (*((PBYTE)pFunctionAddress) == 0xe9)
            {
                for (WORD idx = 1; idx <= 500; idx++)
                {
                    if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00)
                    {
                        __builtin_memcpy(&wSystemCall, (pFunctionAddress + 4 + idx * DOWN), 2);
                        return wSystemCall;

                    }

                    if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00)
                    {
                        __builtin_memcpy(&wSystemCall, (pFunctionAddress + 4 + idx * UP), 2);
                        return wSystemCall;
                    }

                }
                return FALSE;
            }
            if (*((PBYTE)pFunctionAddress + 3) == 0xe9)
            {
                for (WORD idx = 1; idx <= 500; idx++)
                {
                    if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00)
                    {
                        __builtin_memcpy(&wSystemCall, (pFunctionAddress + 4 + idx * DOWN), 2);
                        return wSystemCall;
                    }

                    if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00)
                    {
                        __builtin_memcpy(&wSystemCall, (pFunctionAddress + 4 + idx * UP), 2);
                        return wSystemCall;
                    }

                }
                return -1;
            }
        }
    }
}