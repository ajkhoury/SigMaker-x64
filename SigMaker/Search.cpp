#include "Misc.h"

bool HasOneHitSig( qSigVector& vecSig )
{
    for (qSigVector::iterator i = vecSig.begin( ); i != vecSig.end( ); i++)
        if ((*i).iHitCount == 1)
            return true;

    return false;
}

int GetOccurenceCount( const qstring& strSig, bool bSkipOut = false )
{
    int iCount = 0;
    ea_t dwAddress = find_binary( inf.min_ea, inf.max_ea, strSig.c_str( ), 16, SEARCH_DOWN );

    if (IsValidEA( dwAddress ))
    {
        do
        {
            if (bSkipOut == true && iCount >= 2)
                return iCount;

            iCount++;
            dwAddress = find_binary( dwAddress + 1, inf.max_ea, strSig.c_str( ), 16, SEARCH_DOWN );
        } while (IsValidEA( dwAddress ));
    }
    else
    {
        dwAddress = find_binary( inf.omin_ea, inf.omax_ea, strSig.c_str( ), 16, SEARCH_DOWN );
        if (IsValidEA( dwAddress ))
        {
            do
            {
                if (bSkipOut == true && iCount >= 2)
                    return iCount;
                iCount++;
                dwAddress = find_binary( dwAddress + 1, inf.omax_ea, strSig.c_str( ), 16, SEARCH_DOWN );
            } while (IsValidEA( dwAddress ));
        }
    }

    return iCount;
}

void SearchForSigs( const qstring& strSig )
{
    ea_t dwAddress = find_binary( inf.min_ea, inf.max_ea, strSig.c_str( ), 16, SEARCH_DOWN );

    const char* pszMessage = "===========================\n";

    msg( pszMessage );

    if (IsValidEA( dwAddress ))
    {
        do
        {
#ifdef __EA64__
			msg("sig found at 1%X\n", dwAddress);
#else
			msg("sig found at %X\n", dwAddress);
#endif
            dwAddress = find_binary( dwAddress + 1, inf.max_ea, strSig.c_str( ), 16, SEARCH_DOWN );
        } while (IsValidEA( dwAddress ));
    }
    else
    {
        dwAddress = find_binary( inf.omin_ea, inf.omax_ea, strSig.c_str( ), 16, SEARCH_DOWN );

        if (IsValidEA( dwAddress ))
        {
            do
            {
#ifdef __EA64__
                msg( "sig found at 1%X\n", dwAddress );
#else
				msg("sig found at %X\n", dwAddress);
#endif
                dwAddress = find_binary( dwAddress + 1, inf.omax_ea, strSig.c_str( ), 16, SEARCH_DOWN );
            } while (IsValidEA( dwAddress ));
        }
    }
    msg( pszMessage );
}

void ShowSearchDialog( const char* pszSignature, const char* pszMask )
{
    static const char szForm[] =
        "Test Sig\n"
        "\n"
        "\n"
        "  <Signature:A5:100:100::>\n"
        "  <Mask:A6:100:100::>\n"
        "\n";

    char szSignature[MAXSTR] = { 0 }, szMask[MAXSTR] = { 0 };
    qstring strSig = "";

    if (pszSignature)
        qstrncpy( szSignature, pszSignature, sizeof( szSignature ) );

    if (pszMask)
        qstrncpy( szMask, pszMask, sizeof( szMask ) );

    if (ask_form( szForm, szSignature, szMask ) > 0)
    {
        show_wait_box( "please wait..." );

        //msg( "%s %s\n", szSignature, szMask );

        CodeToIDAC( strSig, szSignature, szMask );

        if (Settings.iLogLevel >= 3)
            msg( "%s = %s %s\n", strSig.c_str( ), szSignature, szMask );

        SearchForSigs( strSig ); //*/

        hide_wait_box( );
    }
}

void ShowSearchDialog( void )
{
    char szSignature[MAXSTR] = { 0 }, szMask[MAXSTR] = { 0 };

    qstring strSig, strSigCode;
    ea_t dwStart, dwEnd;

    if (read_range_selection( get_current_viewer( ), &dwStart, &dwEnd ))
    {
        if (dwEnd - dwStart > 5)
        {
            insn_t cmd;

            func_item_iterator_t fIterator;
            bool isWithinRange = fIterator.set_range( dwStart, dwEnd );

            for (ea_t dwCurrentInstruction = fIterator.current( );
                decode_insn( &cmd, dwCurrentInstruction ) != 0;
                dwCurrentInstruction = fIterator.current( ))
            {
                if (cmd.size < 5)
                    AddBytesToSig( strSig, dwCurrentInstruction, cmd.size );
                else
                    AddInsToSig( &cmd, strSig );

                if (fIterator.next_not_tail( ) == false)
                    break;
            }
        }
    }

    if (strSig.length( ) < 3)
        return;

    IDAToCode( strSig, strSigCode, szMask );

    qstrncpy( szSignature, strSigCode.c_str( ), sizeof( szSignature ) );

    ShowSearchDialog( szSignature, szMask );
}

void ShowSearchWindow( void )
{
    static const char szForm[] =
        "Test Sig\n"
        "\n"
        "\n"
        "  <Signature:A5:100:100::>\n"
        "\n";

    qstring strSig;
    ea_t dwStart, dwEnd;

    if (read_range_selection( get_current_viewer( ), &dwStart, &dwEnd ))
    {
        if (dwEnd - dwStart > 5)
        {
            insn_t cmd;

            func_item_iterator_t fIterator;
            bool isWithinRange = fIterator.set_range( dwStart, dwEnd );

            for (ea_t dwCurrentInstruction = fIterator.current( );
                decode_insn( &cmd, dwCurrentInstruction ) != 0;
                dwCurrentInstruction = fIterator.current( ))
            {
                if (cmd.size < 5)
                    AddBytesToSig( strSig, dwCurrentInstruction, cmd.size );
                else
                    AddInsToSig( &cmd, strSig );

                if (fIterator.next_not_tail( ) == false)
                    break;
            }
        }
    }

    char szSignature[MAXSTR] = { 0 };

    if (strSig.length( ) > 3)
        qstrncpy( szSignature, strSig.c_str( ), sizeof( szSignature ) );

    if (ask_form( szForm, szSignature ) > 0)
    {
        show_wait_box( "please wait..." );
        qstring strSig = szSignature;
        SearchForSigs( strSig );
        hide_wait_box( );
    }
}