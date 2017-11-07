#include "Includes.h"
#include "Misc.h"
 
void ShowOptions( void )
{
    char szBuffer[MAXSTR];
    qsnprintf( szBuffer, MAXSTR - 1, "%i", Settings.iMaxRefCount );

    int iResult = ask_form(
        "Options\n"
        "<##choose the best sig from total length:R>\n" // 0
        "<##choose the best sig from the amount of opcodes:R>\n" // 1
        "<##choose the best sig by the smallest amount of wildcards:R>>\n\n" // 2
        "<max. refs for auto generation(no limit = 0)\n:A2:100:10::>\n"
        "<##add only relilable data to sigs(choose if unsure):R>\n" // 0
        "<##include unsafe data in sigs(may produce better results):R>>\n\n" // 1
        "<##disable logging:R>\n" // 0
        "<##log results:R>\n" // 1
        "<##log errors and results:R>\n" // 2
        "<##log errors, results and interim steps of all proceedures:R>>\n\n" // 3
        , &Settings.iSelectionType, szBuffer, &Settings.iKeepUnsafeData, &Settings.iLogLevel );

    qsscanf( szBuffer, "%i", &Settings.iMaxRefCount );

    Settings.Save( "sigmaker.ini" );
}

bool idaapi run( size_t /*arg*/ )
{
    int iAction = 0;
    int iResult = ask_form(
        "What do you want to do?\n"
        "<##create ida pattern from selection:R>\n" // 0
        "<##create code pattern from selection:R>\n" // 1
        "<##create crc32 pattern from selection:R>\n" // 2
        "<##auto create ida pattern:R>\n" // 3
        "<##auto create code pattern:R>\n" // 4
        "<##auto create crc32 pattern:R>\n" // 5
        "<##test ida pattern:R>\n" // 6
        "<##test code pattern:R>\n" // 7
        "<##convert a sig:R>\n" // 8
        "<##configure the plugin:R>>\n\n", // 9
        &iAction );

    if (iResult > 0)
    {
        switch (iAction)
        {
        case 0: 
            CreateSig( SIG_IDA );
            break;
        case 1: 
            CreateSig( SIG_CODE );
            break;
        case 2: 
            CreateSig( SIG_CRC );
            break;
        case 3: 
            GenerateSig( SIG_IDA );
            break;
        case 4: 
            GenerateSig( SIG_CODE );
            break;
        case 5: 
            GenerateSig( SIG_CRC );
            break;
        case 6: 
            ShowSearchWindow( );
            break;
        case 7: 
            ShowSearchDialog( );
            break;
        case 8: 
            ShowSigConverter( );
            break;
        case 9: 
            ShowOptions( );
            break;
        }
    }

    return true;
}

int __stdcall init( void )
{
    if (inf.filetype != f_PE)
        return PLUGIN_SKIP;

    Settings.Init( );
    Settings.Load( "sigmaker.ini" );

    return PLUGIN_OK;
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_KEEP,
    init,
    NULL,
    run,
    "creates a sigs",
    "SigMaker plugin\n",
    "SigMaker",
    "Ctrl-Alt-S"// Alt-F11
};