#ifndef KAYNINJECT_KAYNINJECT_H
#define KAYNINJECT_KAYNINJECT_H

#include <windows.h>

#define RVA_2_VA( T, B, R ) (T)( (PBYTE) B + R )

DWORD   HashStringA(PCHAR String);
DWORD   KaynOffset( LPVOID lpBuffer, DWORD dwKaynEntryHash );
LPVOID  KaynInject ( HANDLE hProcess, LPVOID lpBuffer, DWORD dwBufferSize, LPVOID lpParameter );

#endif
