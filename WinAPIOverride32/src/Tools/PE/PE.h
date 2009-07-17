/*
Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>
Dynamic aspect ratio code Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>

Reference
An In-Depth Look into the Win32 Portable Executable File Format, Part 1
An In-Depth Look into the Win32 Portable Executable File Format, Part 2 
from Matt Pietrek 

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

//-----------------------------------------------------------------------------
// Object: PE helper
//-----------------------------------------------------------------------------

#pragma once
#include <windows.h>
#include <stdio.h>
#include <delayimp.h>
#include "../APIError/APIError.h"
#include "../LinkList/LinkList.h"
//#include "../String/AnsiUnicodeConvert.h"
#include "../Dll/DllFinder.h"
#pragma warning (push)
#pragma warning(disable : 4005)// for '_stprintf' : macro redefinition in tchar.h
#include <TCHAR.h>
#pragma warning (pop)


// this class is just a begin of pe parsing 

class CPE
{
protected:
    BOOL bNtHeaderParsed;
    BOOL GetRVASectionLimits(DWORD KnownRVABelongingToSection,DWORD* pStart,DWORD* pEnd);
    BOOL ParseIMAGE_SECTION_HEADER();
    BOOL ParseIMAGE_NT_HEADERS();
    BOOL ParseExportTable();
    BOOL ParseImportTable();
    BOOL ParseDelayImportTable();
    void RemoveImportTableItems();
    BOOL GetOrdinalImportedFunctionName(WORD Ordinal,CPE* pPe,OUT TCHAR* FunctionName);
    unsigned char* pBeginOfFile;
    void ShowError(TCHAR* pcMsg);
    TCHAR pcFilename[MAX_PATH];
public:
    typedef struct tagImportItem
    {
        TCHAR LibraryName[MAX_PATH];
        CLinkList* pFunctions; // list of IMPORT_FUNCTION_ITEM
    }IMPORT_LIBRARY_ITEM,*PIMPORT_LIBRARY_ITEM;

    typedef struct tagImportFunctionItem
    {
        TCHAR FunctionName[MAX_PATH];
        WORD Hint;
        WORD Ordinal;
        BOOL bOrdinalOnly;
    }IMPORT_FUNCTION_ITEM,*PIMPORT_FUNCTION_ITEM;

    typedef struct tagExportFunctionItem
    {
        TCHAR FunctionName[MAX_PATH];
        DWORD FunctionAddressRVA;
        WORD Hint;
        WORD ExportedOrdinal;
        BOOL  Forwarded;                // TRUE if function is forwarded
        TCHAR ForwardedName[MAX_PATH];  // DllName.EntryPointName
    }EXPORT_FUNCTION_ITEM,*PEXPORT_FUNCTION_ITEM;

    CPE(TCHAR* filename);
    ~CPE(void);
    BOOL Parse();
    BOOL Parse(BOOL ParseExportTable,BOOL ParseImportTable);
    BOOL SaveIMAGE_DOS_HEADER();
    BOOL SaveIMAGE_NT_HEADERS();
    BOOL SavePIMAGE_SECTION_HEADER();
    BOOL VaToRva(DWORD VaAddress,DWORD* pRvaAddress);
    BOOL RvaToVa(DWORD RvaAddress,DWORD* pVaAddress);
    BOOL RawToRva(DWORD RawAddress,DWORD* pRvaAddress);
    BOOL RvaToRaw(DWORD RvaAddress,DWORD* pRawAddress);
    BOOL GetOrdinalImportedFunctionName(WORD Ordinal,TCHAR* DllName,OUT TCHAR* FunctionName);
    BOOL Is64Bits();
    DWORD GetUnrebasedVirtualAddress(DWORD RebasedRelativeAddress);
    void GetFileName(TCHAR* pszFilename);

    IMAGE_DOS_HEADER DosHeader;
    // NTHeader.OptionalHeader.DataDirectory index :
    //IMAGE_DIRECTORY_ENTRY_EXPORT          0 
    //IMAGE_DIRECTORY_ENTRY_IMPORT          1 
    //IMAGE_DIRECTORY_ENTRY_RESOURCE        2 
    //IMAGE_DIRECTORY_ENTRY_EXCEPTION       3 
    //IMAGE_DIRECTORY_ENTRY_SECURITY        4 
    //IMAGE_DIRECTORY_ENTRY_BASERELOC       5 
    //IMAGE_DIRECTORY_ENTRY_DEBUG           6 
    //IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7 
    //IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7 
    //IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8 
    //IMAGE_DIRECTORY_ENTRY_TLS             9 
    //IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10 
    //IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11 
    //IMAGE_DIRECTORY_ENTRY_IAT            12 
    //IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13 
    //IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14 
    IMAGE_NT_HEADERS NTHeader;

    // size of pSectionHeaders is in NTHeader.FileHeader.NumberOfSections
    IMAGE_SECTION_HEADER* pSectionHeaders;

    CLinkList* pImportTable; // list of IMPORT_LIBRARY_ITEM
    CLinkList* pExportTable; // list of EXPORT_FUNCTION_ITEM
};
