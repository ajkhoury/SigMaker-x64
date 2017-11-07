#pragma once

#include "Includes.h"

#define IsValidEA( x ) x != 0 && x != BADADDR

enum ePatternType {
    PT_DIRECT,
    PT_FUNCTION,
    PT_REFERENCE
};

struct AutoSig_t {
    qstring strSig;
    ea_t dwStartAddress;
    ea_t dwCurrentAddress;
    int iHitCount;
    unsigned int iOpCount;
    ePatternType eType;
};
typedef qvector<AutoSig_t> qSigVector;


typedef enum {
    SIG_IDA,
    SIG_CODE,
    SIG_CRC,
} SigType;

struct Settings_t {
    int iSelectionType;
    unsigned int iMaxRefCount;
    int iKeepUnsafeData;
    int iLogLevel;

    void Init( void );
    void Save( const char* pszFileName );
    void Load( const char* pszFileName );
};

extern Settings_t Settings;

// search.cpp
void ShowSearchDialog( void );
void ShowSearchWindow( void );
bool HasOneHitSig( qSigVector& vecSig );
int GetOccurenceCount( const qstring& strSig, bool bSkipOut );
void SearchForSigs( const qstring& strSig );
void ShowSearchDialog( const char* pszSignature, const char* pszMask );

// generate.cpp
void CreateSig( SigType eType );
void GenerateSig( SigType eType );
bool AutoGenerate( qSigVector& vecSig, ea_t dwAddress );
bool AddOneInstructionToSig( qstring& strSig, ea_t& dwCurentAddress );
void AddInsToSig( insn_t *cmd, qstring& strSig );
bool MatchOperands( insn_t *cmd, unsigned int uiOperand, unsigned int uiSize );
unsigned int getCurrentOpcodeSize( insn_t *cmd, unsigned int& uiCount );
void AddBytesToSig( qstring& strSig, ea_t dwAddress, ea_t dwSize );
void AddWhiteSpacesToSig( qstring& strSig, ea_t dwSize );

// converter.cpp
void IDAToCode( const qstring& strSig, qstring& pszByteSig, char* pszMask );
void CodeToIDA( qstring& strSig, const qstring& strByteSig, const qstring& strMask );
void IDAToCRC( const qstring& strSig, ea_t& dwCRC32, ea_t& dwMask );
void CodeToCRC( const qstring& strByteSig, const qstring& strMask, ea_t& dwCRC32, ea_t& dwMask );
void CodeToIDAC( qstring& strSig, const char* strByteSig, const char* strMask );
void ShowSigConverter( void );

// platform.cpp
bool TextToClipboard( const char* pszText );
