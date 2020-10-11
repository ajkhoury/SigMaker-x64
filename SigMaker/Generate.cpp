#include "Misc.h"

void AddBytesToSig( qstring& strSig, ea_t dwAddress, ea_t dwSize )
{
    for (ea_t i = 0; i < dwSize; i++)
        strSig.cat_sprnt( "%02X ", get_byte( dwAddress + i ) );
}

void AddWhiteSpacesToSig( qstring& strSig, ea_t dwSize )
{
    for (ea_t i = 0; i < dwSize; i++)
        strSig.cat_sprnt( "? " );
}

unsigned int getCurrentOpcodeSize( insn_t *cmd, unsigned int& uiCount )
{
    for (unsigned int i = 0; i < UA_MAXOP; i++)
    {
        uiCount = i;
        if (cmd->ops[i].type == o_void)
            return 0;
        if (cmd->ops[i].offb != 0)
            return cmd->ops[i].offb;
    }
    return 0;
}

bool MatchOperands( insn_t *cmd, unsigned int uiOperand, unsigned int uiSize ) // this is where all the options kick in
{
    //if ( cmd.Operands[ uiOperand ].type == o_mem || cmd.Operands[ uiOperand ].type == o_far)
    //	return false;

    if (get_first_dref_from( cmd->ea ) != BADADDR) // data reference
        return false;

    if (Settings.iKeepUnsafeData != 0)
    {
        if (get_first_fcref_from( cmd->ea ) != BADADDR) // code reference
            return false;
    }
    else
    {
        if (get_first_cref_from( cmd->ea ) != BADADDR) // code reference
            return false;
    }

    return true;
}

void AddInsToSig( insn_t *cmd, qstring& strSig )
{
    unsigned int uiCount = 0;
    unsigned int uiSize = getCurrentOpcodeSize( cmd, uiCount );
    if (uiSize == 0)
    {
        AddBytesToSig( strSig, cmd->ea, cmd->size );
        return;
    }

    AddBytesToSig( strSig, cmd->ea, uiSize );

    if (MatchOperands( cmd, 0, uiSize ))
        AddBytesToSig( strSig, cmd->ea + uiSize, cmd->size - uiSize );
    else
        AddWhiteSpacesToSig( strSig, cmd->size - uiSize );
}

bool AddOneInstructionToSig( qstring& strSig, ea_t& dwCurentAddress )
{
    insn_t cmd;

    if (decode_insn( &cmd, dwCurentAddress ) == 0)
        return false;

    if (cmd.size == 0) // prevent an infinite loop
        return false;

    if (cmd.size < 5)
        AddBytesToSig( strSig, dwCurentAddress, cmd.size );
    else
        AddInsToSig( &cmd, strSig );

    dwCurentAddress += cmd.size;
    return true;
}

bool AutoGenerate( ea_t dwAddress, qSigVector& refvecSig )
{
    qSigVector vecSig; // remove previous entries

    show_wait_box( "Please Wait..." );

    unsigned int nTotalCount = 0;

    refvecSig.clear( );

    if (get_func_num( dwAddress ) != -1) // this just a check to see if the function is valid code
    {
        AutoSig_t TargetLocation;
        TargetLocation.dwStartAddress = TargetLocation.dwCurrentAddress = dwAddress;
        TargetLocation.iOpCount = 0;
        TargetLocation.eType = PT_DIRECT;
        vecSig.push_back( TargetLocation );
        nTotalCount++;
        if (Settings.iLogLevel >= 3)
        {
            msg( "A direct signature is available for the current address.\n" );
        }
    }

    msg( "adding references\n" );

    // got references?
    for (ea_t dwCurrent = get_first_cref_to( dwAddress );
        dwCurrent != BADADDR;
        dwCurrent = get_next_cref_to( dwAddress, dwCurrent ))
    {
        if (dwCurrent == dwAddress)
            continue;

        AutoSig_t TargetLocation;
        TargetLocation.dwStartAddress = TargetLocation.dwCurrentAddress = dwCurrent;
        TargetLocation.iOpCount = 0;
        TargetLocation.eType = PT_REFERENCE;
        vecSig.push_back( TargetLocation );

        nTotalCount++;

        if (Settings.iMaxRefCount > 0)
        {
            if (nTotalCount >= Settings.iMaxRefCount)
                break;
        }      
    }

    if (Settings.iLogLevel >= 3 && nTotalCount > 1)
    {
        msg( "Added %i references to the selected address.\n", nTotalCount - 1 );
    }

    if (nTotalCount < 5) // we are pointing at data
    {
        func_t* pFunc = get_func( dwAddress );

        if (Settings.iLogLevel >= 3)
        {
            msg( "Not enough references were found (%i so far), trying the function.\n", nTotalCount );
        }

        if (pFunc && pFunc->start_ea != dwAddress)
        {
            if (Settings.iLogLevel >= 3)
            {
                msg( "the function seems valid scanning...\n" );
            }
            for (ea_t dwCurrent = get_first_cref_to( pFunc->start_ea );
                dwCurrent != BADADDR;
                dwCurrent = get_next_cref_to( pFunc->start_ea, dwCurrent ))
            {
                if (dwCurrent == dwAddress)
                    continue;

                AutoSig_t TargetLocation;
                TargetLocation.dwStartAddress = pFunc->start_ea;
                TargetLocation.dwCurrentAddress = dwCurrent;
                TargetLocation.iOpCount = 0;
                TargetLocation.eType = PT_FUNCTION;
                vecSig.push_back( TargetLocation );

                nTotalCount++;

                if (Settings.iMaxRefCount > 0)
                {
                    if (nTotalCount >= Settings.iMaxRefCount)
                        break;
                }
            }
        }
        else
        {
            if (Settings.iLogLevel >= 2)
            {
                msg( "the function was invalid...\n" );
            }
        }
    }

    if (Settings.iLogLevel >= 2)
    {
        msg( "added a total of %i references.\n", nTotalCount );
    }

    int iCount = 0;

    do
    {
        if (nTotalCount < 1) // vecSig.size()
        {
            hide_wait_box( );

            if (Settings.iLogLevel >= 2)
            {
                msg( "automated signature generation failed. Unable to proceed.\n" );
            }

            return false;
        }

        for (size_t i = 0; i < vecSig.size( ); i++)
        {
            if (AddOneInstructionToSig( vecSig[i].strSig, vecSig[i].dwCurrentAddress ))
            {
                vecSig[i].iOpCount++;
                vecSig[i].iHitCount = (vecSig[i].strSig.length( ) > 5) ? GetOccurenceCount( vecSig[i].strSig, true ) : 0;
            }
            else
            {
                if (Settings.iLogLevel >= 2)
                {
                    msg( "dropped a sig due to decompilation failure.\n" );
                }

                if ( vecSig.empty( ) )
                {
                    hide_wait_box( );
                    msg( "not enough candidates to proceed. aborting...\n" );
                    return false;
                }

                vecSig.erase( vecSig.begin( ) + i );
                i--;
            }            
        }
    } while (HasOneHitSig( vecSig ) == false && !vecSig.empty( ) );

    refvecSig.clear( );


    for (AutoSig_t& iterSig : vecSig)
    {
        if (iterSig.iHitCount == 1)
        {
            if (Settings.iLogLevel >= 3)
            {
                // remove trailing whitespace from signature
                if (!iterSig.strSig.empty() && iterSig.strSig.last() == ' ')
                    iterSig.strSig.remove_last();

                msg( "[%x] Signature %s is a viable candidate for final evaluation.\n", iterSig.dwStartAddress, iterSig.strSig.c_str( ) );
            }

            refvecSig.push_back( iterSig );
        }
    }

    hide_wait_box( );
    vecSig.clear( );

    return (refvecSig.size( ) != 0);
}


void CreateSig( SigType eType )
{
    qstring strSig;
    ea_t dwStart, dwEnd;

    if (read_range_selection( get_current_viewer( ), &dwStart, &dwEnd ))
    {
        if (dwEnd - dwStart < 5)
        {
            msg( "Your selection is too short!\n" );
            return;
        }

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

        if (Settings.iLogLevel >= 2)
            msg( "sig %s\n", strSig.c_str( ) );
    }
    else
    {
        if (Settings.iLogLevel >= 1)
        {
            msg( "no code selected.\n" );
        }
        return;
    }

    qstring strTmp;
    char szMask[MAXSTR];

    switch (eType)
    {
    case SIG_IDA:
        break;
    case SIG_CODE:
        IDAToCode( strSig, strTmp, szMask );
        strSig.sprnt( "%s, %s", strTmp.c_str( ), szMask );
        break;
    case SIG_CRC:
        IDAToCRC( strSig, dwStart, dwEnd );
        strSig.sprnt( "0x%X, 0x%X", dwStart, dwEnd );
        break;
    }

    TextToClipboard( strSig.c_str( ) );

    if (Settings.iLogLevel >= 1)
    {
        msg( "Sig: %s\n", strSig.c_str( ) );
    }
}

unsigned int GetCharCount( const char* pszString, char chSign, bool bCaseInsenstive = false )
{
    unsigned int nLength = 0;

    do
    {
        if (bCaseInsenstive)
        {
            if (qtolower( *pszString ) == qtolower( chSign ))
                nLength++;
        }
        else
        {
            if (*pszString == chSign)
                nLength++;
        }
    } while (*pszString++);

    return nLength;
}

void GenerateSig( SigType eType )
{
    qSigVector vecSig;
    qSigVector::iterator iterSig = nullptr;
    size_t uiLength = 9999;

    ea_t dwAddress = get_screen_ea( );

    if (dwAddress == BADADDR)
    {
        if (Settings.iLogLevel >= 2)
        {
            msg( "You must select an address.\n" );
        }
        return;
    }

    if (AutoGenerate( dwAddress, vecSig ))
    {
        for (AutoSig_t& i : vecSig)
        {
            if (Settings.iSelectionType == 0)
            {
                size_t nLength = i.strSig.length( );
                if (uiLength > nLength || (i.eType == PT_DIRECT && uiLength == nLength))
                {
                    uiLength = nLength;
                    iterSig = &i;
                }
            }
            else
            {
                if (Settings.iSelectionType == 1)
                {
                    if (uiLength > i.iOpCount || (i.eType == PT_DIRECT && uiLength == i.iOpCount))
                    {
                        uiLength = i.iOpCount;
                        iterSig = &i;
                    }
                }
                else
                {
                    unsigned int nLength = GetCharCount( i.strSig.c_str( ), '?' );

                    if (uiLength > nLength || (i.eType == PT_DIRECT && uiLength == nLength))
                    {
                        uiLength = nLength;
                        iterSig = &i;
                    }
                }
            }
        }
    }
    else
    {
        msg("Failed to automatically generate signature at %X\n", dwAddress);
        return;
    }

    if(iterSig == nullptr) {
        msg("iterSig is null (this should never happen) %X\n", dwAddress);
        return;
    }

    qstring strSig = iterSig->strSig, strTmp;
    char szMask[MAXSTR];
    ea_t dwStart, dwEnd;

    switch (eType)
    {
    case SIG_IDA:
        break;
    case SIG_CODE:
        IDAToCode( strSig, strTmp, szMask );
        strSig.sprnt( "%s, %s", strTmp.c_str( ), szMask );
        break;
    case SIG_CRC:
        IDAToCRC( strSig, dwStart, dwEnd );
        strSig.sprnt( "0x%X, 0x%X", dwStart, dwEnd );
        break;
    }

    TextToClipboard( strSig.c_str( ) );

    if (Settings.iLogLevel >= 1)
    {
        const ea_t delta = dwAddress - iterSig->dwStartAddress;

        switch (iterSig->eType)
        {
        case PT_DIRECT:
            msg( "raw sig: %s\n", strSig.c_str( ) );
            break;
        case PT_FUNCTION:
            msg( "function + offset sig: (+0x%X) %s\n", delta, strSig.c_str( ) );
            break;
        case PT_REFERENCE:
            if(delta > 0)
              msg( "direct reference sig: (+0x%X) %s\n", delta, strSig.c_str( ) );
            else
              msg( "direct reference sig: %s\n", strSig.c_str());

            break;
        }
    }
}
