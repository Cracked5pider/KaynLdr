/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 * Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
 */

#include <KaynLdr.h>
#include <Win32.h>

HINSTANCE hAppInstance = NULL;

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
    switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *(HMODULE *)lpReserved = hAppInstance;
            break;
        case DLL_PROCESS_ATTACH:
        {
            hAppInstance = hinstDLL;
            MessageBoxA( NULL, "Hello from KaynLdr", "KaynLdr", MB_OK );
            break;
        }

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}