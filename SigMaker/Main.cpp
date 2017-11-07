#include "Includes.h"
#include "Misc.h"
 
void ShowOptions( void )
{
    ushort selectionType, keepUnsafeData, logLevel;
    char szBuffer[MAXSTR] = { 0 };

    selectionType = (ushort)Settings.iSelectionType;
    keepUnsafeData = (ushort)Settings.iKeepUnsafeData;
    logLevel = (ushort)Settings.iLogLevel;
    _itoa_s( Settings.iMaxRefCount, szBuffer, MAXSTR, 10 );

    int iResult = ask_form( 
        "Options\n"
        "<#Choose the best sig from total length:R>\n" // 0
        "<#Choose the best sig from the amount of opcodes:R>\n" // 1
        "<#Choose the best sig by the smallest amount of wildcards:R>>\n" // 2
        "<Maximum refs for auto generation:A:20:10::>\n"
        "<#Add only relilable data to sigs(choose if unsure):R>\n" // 0
        "<#Include unsafe data in sigs(may produce better results):R>>\n" // 1
        "<#Disable logging:R>\n" // 0
        "<#Log results:R>\n" // 1
        "<#Log errors and results:R>\n" // 2
        "<#Log errors, results and interim steps of all proceedures:R>>\n" // 3
        , &selectionType, szBuffer, &keepUnsafeData, &logLevel );

    if (iResult > 0)
    {
        Settings.iSelectionType = selectionType;
        Settings.iKeepUnsafeData = keepUnsafeData;
        Settings.iLogLevel = logLevel;
        qsscanf( szBuffer, "%i", &Settings.iMaxRefCount );      
        Settings.Save( "sigmaker.ini" );
    }
}

bool idaapi run( size_t /*arg*/ )
{
    int iAction = 0;

    int iResult = ask_form(
        "What do you want to do?\n"
        "<#Auto create ida pattern:R>\n" // 0
        "<#Auto create code pattern:R>\n" // 1
        "<#Auto create crc32 pattern:R>\n" // 2
        "<#Create ida pattern from selection:R>\n" // 3
        "<#Create code pattern from selection:R>\n" // 4
        "<#Create crc32 pattern from selection:R>\n" // 5
        "<#Test ida pattern:R>\n" // 6
        "<#Test code pattern:R>\n" // 7
        "<#Convert a sig:R>\n" // 8
        "<#Configure the plugin:R>>\n\n" // 9
        , &iAction );

    if (iResult > 0)
    {
        switch (iAction)
        {
        case 0:
            GenerateSig( SIG_IDA );
            break;
        case 1:
            GenerateSig( SIG_CODE );
            break;
        case 2:
            GenerateSig( SIG_CRC );
            break;
        case 3: 
            CreateSig( SIG_IDA );
            break;
        case 4: 
            CreateSig( SIG_CODE );
            break;
        case 5: 
            CreateSig( SIG_CRC );
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

int idaapi init( void )
{
    if (inf.filetype != f_PE)
        return PLUGIN_SKIP;

    Settings.Init( );
    Settings.Load( "sigmaker.ini" );

    return PLUGIN_OK;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_KEEP,
    init,
    NULL,
    run,
    "Creates a unique signature",
    "SigMaker plugin",
    "SigMaker",
    "Ctrl-Alt-S"
};