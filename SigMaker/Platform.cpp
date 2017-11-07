// this file shall be used to implement platform dependant features

// NT Platform
#define __NT__

#ifdef __NT__
#include <Windows.h>

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "ida.lib")
#pragma comment(lib, "pro.lib")

bool TextToClipboard( const char* pszText )
{
    bool bResult = false;

    if (OpenClipboard( NULL ))
    {
        if (EmptyClipboard( ))
        {
            size_t iDataSize = (strlen( pszText ) + 1);
            if (iDataSize > 1)
            {
                HGLOBAL hTextMem = GlobalAlloc( GMEM_MOVEABLE, iDataSize );
                if (hTextMem)
                {
                    char* pTextMem = (char*)GlobalLock( hTextMem );
                    if (pTextMem)
                    {
                        memcpy( pTextMem, pszText, iDataSize );
                        GlobalUnlock( hTextMem );
                        bResult = (SetClipboardData( CF_TEXT, hTextMem ) != NULL);
                    }
                }
            }
        }
        // no freeing needed windows now owns our memory
        CloseClipboard( );
    }

    return bResult;
}

int __stdcall DllMain( HMODULE hModule, DWORD dwReason, LPVOID lpReserved )
{
    return 1;
}

#else
bool TextToClipboard( const char* pszText )
{
    return false; // got a mac or linux?
}
#endif // __NT__*/