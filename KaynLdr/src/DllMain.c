/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 */

#include <KaynLdr.h>
#include <Win32.h>

HINSTANCE hAppInstance = NULL;

BOOL WINAPI DllMain( HINSTANCE hInstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;

    switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *( HMODULE* ) lpReserved = hAppInstance;
            break;

        case DLL_PROCESS_ATTACH:
        {
            hAppInstance     = hInstDLL;

            PCHAR HelloMsg   = "Hello from KaynLdr";
            PCHAR Buffer     = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, strlen( HelloMsg ) + 1 );

            memcpy( Buffer, HelloMsg, strlen( HelloMsg ) + 1 );

            MessageBoxA( NULL, Buffer, "KaynLdr", MB_OK );
            HeapFree( GetProcessHeap(), 0, Buffer );
            memset( Buffer, 0, strlen( HelloMsg ) );

            ExitProcess( 0 );
        }

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}