#include "Includes.h"
#include "Misc.h"

void ShowSigConverter( void )
{
    static const char szForm[] =
        "Sig Converter\n"
        "\n"
        "\n"
        "  <Sig:A5:100:100::>\n"
        "  <Mask:A6:100:100::>\n"
        "\n"
        "  <##Code to IDA:R>\n" // 0
        "  <##Code to CRC:R>\n" // 1
        "  <##IDA to CRC:R>\n" // 2
        "  <##IDA to Code:R>\n" // 3
        "  <##IDA to Olly:R>\n" // 4
        "  <##Olly to IDA:R>>\n" // 5
        "\n"
        "\n";

    char szSigIn[MAXSTR] = { 0 };
    char szMaskIn[MAXSTR] = { 0 };

    ushort usCheckBox = 0;

    qstring strTemp;

    if (ask_form( szForm, szSigIn, szMaskIn, &usCheckBox ) > 0)
    {
        strTemp = szSigIn;
        qstring strSigIn = szSigIn;
        qstring strMaskIn = szMaskIn;
        ea_t dwCRC = 0, dwMask = 0;

        switch (usCheckBox)
        {
        case 0:
            CodeToIDA( strTemp, strSigIn, strMaskIn );
            break;
        case 1:
            CodeToCRC( strSigIn, strMaskIn, dwCRC, dwMask );
            strTemp.sprnt( "0x%x, 0x%x", dwCRC, dwMask );
            break;
        case 2:
            IDAToCRC( strSigIn, dwCRC, dwMask );
            strTemp.sprnt( "0x%x, 0x%x", dwCRC, dwMask );
            break;
        case 3:
            IDAToCode( strTemp, strSigIn, szMaskIn );
            strTemp.sprnt( "%s, %s", szSigIn, szMaskIn );
            break;
        case 4:
            strTemp.replace( " ? ", " ?? " );
            break;
        case 5:
            strTemp.replace( " ?? ", " ? " );
            break;
        }
        if (TextToClipboard( strTemp.c_str( ) ) == false)
        {
            if (Settings.iLogLevel >= 1)
            {
                msg( "Converted: %s\n", strTemp.c_str( ) );
            }
        }
    }
}

bool GetNextByte( char** pszString, unsigned char& rByte, bool& isWhiteSpace )
{
    do
    {
        if (*(*pszString) == '?')
        {
            rByte = 0;
            isWhiteSpace = true;
            *(*pszString)++;

            if (*(*pszString) == '?')
                *(*pszString)++;

            return true;
        }
        else if (qisxdigit( **pszString ))
        {
            isWhiteSpace = false;
            rByte = (unsigned char)(strtoul( *pszString, pszString, 16 ) & 0xFF);
            return true;
        }
    } while (*(*pszString)++);

    return false;
}

int Text2Hex( const char* pszString, unsigned char* pbArray, char* pszMask = NULL )
{
    int Count = 0;
    bool isWhiteSpace = false;

    if (pszMask)
        *pszMask = 0;

    if (GetNextByte( const_cast<char**>(&pszString), pbArray[Count], isWhiteSpace ))
    {
        do
        {
            Count++;

            if (pszMask)
                qstrncat( pszMask, (isWhiteSpace) ? "?" : "x", MAXSTR );

        } while (GetNextByte( const_cast<char**>(&pszString), pbArray[Count], isWhiteSpace ));
    }

    return Count;
}

int CodeStyleToByte( const char* pszSignature, unsigned char* pbArray, char* pszMask )
{
    char szBuffer[MAXSTR] = { 0 };
    char szTemp[2] = { 0 };

    size_t iLength = strlen( pszSignature );

    for (size_t i = 0; i < iLength; i++)
    {
        if (pszSignature[i] == '\\')
        {
            continue;
        }
        else if (pszSignature[i] == 'x')
        {
            qstrncat( szBuffer, " ", sizeof( szBuffer ) );
        }
        else
        {
            szTemp[0] = pszSignature[i];
            qstrncat( szBuffer, szTemp, sizeof( szBuffer ) );
        }
    }

    return Text2Hex( szBuffer, pbArray, pszMask );
}

// To Code conversion
void IDAToCode( const qstring& strSig, qstring& strByteSig, char* pszMask )
{
    unsigned char ucByteArray[MAXSTR];
    int iCount = Text2Hex( strSig.c_str( ), ucByteArray, pszMask );
    strByteSig.clear( );

    for (int i = 0; i < iCount; i++)
        strByteSig.cat_sprnt( "\\x%02X", ucByteArray[i] );
}

// to crc conversion
void IDAToCRC( const qstring& strSig, ea_t& dwCRC32, ea_t& dwMask )
{
    unsigned char ucByteArray[MAXSTR];
    char szMask[MAXSTR];
    int iCount = Text2Hex( strSig.c_str( ), ucByteArray, szMask );

    for (int i = 0; i < 32; i++)
    {
        if (i <= iCount && szMask[i] == 'x')
        {
            dwMask |= (1 << i);
        }
        else
        {
            dwMask &= ~(1 << i);
        }
    }

    dwCRC32 = calc_crc32( 0, ucByteArray, 32 );
}

void CodeToCRC( const qstring& strByteSig, const qstring& strMask, ea_t& dwCRC32, ea_t& dwMask )
{
    unsigned char ucByteArray[MAXSTR];
    char szMask[MAXSTR];
    int iCount = Text2Hex( strByteSig.c_str( ), ucByteArray, szMask );

    for (int i = 0; i < 32; i++)
    {
        if (i <= iCount && szMask[i] == 'x')
        {
            dwMask |= 1 << i;
        }
        else
        {
            dwMask &= ~(1 << i);
        }
    }

    dwCRC32 = calc_crc32( 0, ucByteArray, 32 );
}

// to ida conversation
void CodeToIDA( qstring& strSig, const qstring& strByteSig, const qstring& strMask )
{
    unsigned char ucByteArray[MAXSTR] = { 0 };

    int iCount = Text2Hex( strByteSig.c_str( ), ucByteArray, NULL );

    size_t nLength = strMask.length( );
    strSig.clear( );

    for (size_t i = 0; i < nLength; i++)
    {
        if (strMask[i] == 'x' || strMask[i] == 'X')
        {
            strSig.cat_sprnt( "0x%02X ", ucByteArray[i] );
        }
        else
        {
            strSig += "? ";
        }
    }
}

void CodeToIDAC( qstring& strSig, const char* strByteSig, const char* strMask )
{
    unsigned char ucByteArray[MAXSTR] = { 0 };

    int iCount = Text2Hex( strByteSig, ucByteArray, NULL );

    size_t nLength = qstrlen( strMask );
    strSig.clear( );

    for (size_t i = 0; i < nLength; i++)
    {
        if (strMask[i] == 'x' || strMask[i] == 'X')
        {
            strSig.cat_sprnt( "%02X ", ucByteArray[i] );
        }
        else
        {
            strSig += "? ";
        }
    }
}