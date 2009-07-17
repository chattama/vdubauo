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

#include "pe.h"

CPE::CPE(TCHAR* filename)
{
    this->bNtHeaderParsed=FALSE;
    _tcsncpy(this->pcFilename,filename,MAX_PATH);
    memset(&this->DosHeader,0,sizeof(IMAGE_DOS_HEADER));
    this->pSectionHeaders=NULL;

    this->pImportTable=new CLinkList(sizeof(CPE::IMPORT_LIBRARY_ITEM));
    this->pExportTable=new CLinkList(sizeof(CPE::EXPORT_FUNCTION_ITEM));
}

CPE::~CPE(void)
{
    this->RemoveImportTableItems();
    delete this->pImportTable;
    delete this->pExportTable;

    if (this->pSectionHeaders)
        delete this->pSectionHeaders;
}
void CPE::RemoveImportTableItems()
{
    CLinkListItem* pLinkListItem;
    this->pImportTable->Lock();
    for (pLinkListItem=this->pImportTable->Head;pLinkListItem;pLinkListItem=pLinkListItem->NextItem)
    {
        delete ((CPE::PIMPORT_LIBRARY_ITEM)pLinkListItem->ItemData)->pFunctions;
    }
    this->pImportTable->RemoveAllItems(TRUE);
    this->pImportTable->Unlock();
}
void CPE::ShowError(TCHAR* pcMsg)
{
    UNREFERENCED_PARAMETER(pcMsg);
#if (!defined(TOOLS_NO_MESSAGEBOX))
    MessageBox(NULL,pcMsg,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
#endif
}

//-----------------------------------------------------------------------------
// Name: Parse
// Object: loads DosHeader, NTHeader and pSectionHeaders infos from file
//          don't parse import nor export table
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::Parse()
{
    return this->Parse(FALSE,FALSE);
}

//-----------------------------------------------------------------------------
// Name: Parse
// Object: loads DosHeader, NTHeader and pSectionHeaders infos from file
//          optionally parse import or export table
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::Parse(BOOL ParseExportTable,BOOL ParseImportTable)
{
    BOOL bRes;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID BaseAddress;

    // empty import and export table list
    this->RemoveImportTableItems();
    this->pExportTable->RemoveAllItems();

    // open file
    hFile = CreateFile(this->pcFilename, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile==INVALID_HANDLE_VALUE)
    {
        CAPIError::ShowLastError();
        return FALSE;
    }
    // create file mapping
    hFileMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
    if (!hFileMapping)
    {
        CAPIError::ShowLastError();
        CloseHandle(hFile);
        return FALSE;
    }
    // map view of file
    BaseAddress=MapViewOfFile(hFileMapping,FILE_MAP_READ,0,0,0);

    if (BaseAddress==NULL)
    {
        CAPIError::ShowLastError();
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return FALSE;
    }
    this->pBeginOfFile=(PBYTE)BaseAddress;

    // check for exe
    if (((PIMAGE_DOS_HEADER)this->pBeginOfFile)->e_magic ==IMAGE_DOS_SIGNATURE)
    {
        // store DOS header
        memcpy(&this->DosHeader,this->pBeginOfFile,sizeof(IMAGE_DOS_HEADER));
        // parse NTHeader (and the remaining of the file)
        bRes=this->ParseIMAGE_NT_HEADERS();
        if (bRes)
        {
            bRes=this->ParseIMAGE_SECTION_HEADER();
            if (!bRes)
                this->ShowError(_T("Error parsing IMAGE_SECTION_HEADER"));
        }
        if (bRes&&ParseExportTable)
        {
            bRes=this->ParseExportTable();
            if (!bRes)
                this->ShowError(_T("Error parsing export table"));
        }
        if (bRes&&ParseImportTable)
        {
            bRes=this->ParseImportTable();
            if (!bRes)
                this->ShowError(_T("Error parsing import table"));
        }
    }
    else
    {
        this->ShowError(_T("Unrecognized file format."));
        bRes=FALSE;
    }

    // unmap view of file
    UnmapViewOfFile(BaseAddress);
    // close file mapping
    CloseHandle(hFileMapping);
    // close file
    CloseHandle(hFile);

    return bRes;
}

//-----------------------------------------------------------------------------
// Name: ParseIMAGE_NT_HEADERS
// Object: loads NTHeader infos
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::ParseIMAGE_NT_HEADERS()
{
	PIMAGE_NT_HEADERS pNTHeader;
	
	pNTHeader = (PIMAGE_NT_HEADERS)(this->pBeginOfFile+this->DosHeader.e_lfanew);
	// First, verify that the e_lfanew field gave us a reasonable
	// pointer, then verify the PE signature.
	if (IsBadReadPtr(pNTHeader, sizeof(IMAGE_NT_HEADERS)) ||
	     pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{
        this->ShowError(_T("Error reading IMAGE_NT_HEADERS"));
		return FALSE;
	}
    // store NTHeader
    memcpy(&this->NTHeader,pNTHeader,sizeof(IMAGE_NT_HEADERS));

    this->bNtHeaderParsed=TRUE;

    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: ParseIMAGE_SECTION_HEADER
// Object: loads pSectionHeaders infos
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::ParseIMAGE_SECTION_HEADER()
{
    PIMAGE_SECTION_HEADER pSecHeader;
    // get sections informations
    pSecHeader=(PIMAGE_SECTION_HEADER)(this->pBeginOfFile+this->DosHeader.e_lfanew+sizeof(IMAGE_NT_HEADERS));
    if (IsBadReadPtr(pSecHeader, sizeof(IMAGE_SECTION_HEADER)*this->NTHeader.FileHeader.NumberOfSections))
	{
        this->ShowError(_T("Error in Sections Header"));
		return FALSE;
	}
    // free previous section headers if any
    if (this->pSectionHeaders!=NULL)
        delete this->pSectionHeaders;
    // allocate memory and copy data
    this->pSectionHeaders=new IMAGE_SECTION_HEADER[this->NTHeader.FileHeader.NumberOfSections];
    // get all sections infos
    memcpy(this->pSectionHeaders,pSecHeader,sizeof(IMAGE_SECTION_HEADER)*this->NTHeader.FileHeader.NumberOfSections);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: ParseExportTable
// Object: parse the export table. Content of the export table is stored in 
//              CPE::pExportTable (list of EXPORT_FUNCTION_ITEM)
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::ParseExportTable()
{
    // empty export table list
    this->pExportTable->RemoveAllItems();

    // if no export
    if (this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress==NULL)
        return TRUE;

    DWORD dwRawAddress;
    IMAGE_EXPORT_DIRECTORY* pExportDirectory;
    CPE::EXPORT_FUNCTION_ITEM ExportFunctionItem={0};
    char** pFunctionName=0;
    PDWORD pFunctionAddress;
    PWORD pFunctionOrdinal=0;
    BOOL bFound;
    DWORD cnt2;
    DWORD ForwardedNameAddress;
    DWORD IMAGE_DIRECTORY_ENTRY_EXPORT_StartAddressRVA;
    DWORD IMAGE_DIRECTORY_ENTRY_EXPORT_EndAddressRVA;
    WORD Ordinal;
    char* pstrFunctionName;
    BOOL bNoNames=FALSE;// for ordinal export dll only
    BOOL bNoOrdinals;
#if (defined(UNICODE)||defined(_UNICODE))
    TCHAR* psz;
#endif

    // get limits of IMAGE_DIRECTORY_ENTRY_EXPORT DataDirectory to check fo forwarded funcs
    IMAGE_DIRECTORY_ENTRY_EXPORT_StartAddressRVA=(DWORD)this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_DIRECTORY_ENTRY_EXPORT_EndAddressRVA=IMAGE_DIRECTORY_ENTRY_EXPORT_StartAddressRVA+
                                            this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (!this->RvaToRaw(IMAGE_DIRECTORY_ENTRY_EXPORT_StartAddressRVA,&dwRawAddress))
        return FALSE;

    pExportDirectory=(IMAGE_EXPORT_DIRECTORY*)(this->pBeginOfFile+dwRawAddress);

    // convert RVA pointers to RAW pointer, and next make them point to our file mapping
    if (!this->RvaToRaw(pExportDirectory->AddressOfFunctions,&dwRawAddress))
        return FALSE;
    pFunctionAddress=(DWORD*)(this->pBeginOfFile+dwRawAddress);

    if (pExportDirectory->AddressOfNameOrdinals)
    {
        bNoOrdinals=FALSE;
        if (!this->RvaToRaw(pExportDirectory->AddressOfNameOrdinals,&dwRawAddress))
            return FALSE;
        pFunctionOrdinal=(WORD*)(this->pBeginOfFile+dwRawAddress);
    }
    else
        bNoOrdinals=TRUE;

    if ((pExportDirectory->AddressOfNames==0)||(pExportDirectory->NumberOfNames==0))
        bNoNames=TRUE;
    else
    {
        if (!this->RvaToRaw(pExportDirectory->AddressOfNames,&dwRawAddress))
            return FALSE;
        pFunctionName=(char**)(this->pBeginOfFile+dwRawAddress);
    }

    // for each exported func
    for (DWORD cnt=0; cnt < pExportDirectory->NumberOfFunctions; cnt++, pFunctionAddress++)
    {

        if (*pFunctionAddress==0)// Skip over gaps in exported function ordinals
            continue;            // (the entry point is 0 for these functions)


        bFound=FALSE;

        // get func address
        ExportFunctionItem.FunctionAddressRVA=*pFunctionAddress;

        *ExportFunctionItem.FunctionName=0;
        if (!bNoOrdinals)
        {
            // Get function Hint
            for ( cnt2=0; cnt2 < pExportDirectory->NumberOfFunctions; cnt2++ )
            {
                // if func number is found in it
                if ( pFunctionOrdinal[cnt2] != cnt )
                    continue;

                ExportFunctionItem.Hint=(WORD)cnt2;
                bFound=TRUE;
                break;
            }
        }

        if(!bFound)// can appear on some dll. Avoid to return FALSE as the remaining funcs are ok
            continue;

        // get func name
        if (bFound && (!bNoNames) && (ExportFunctionItem.Hint<pExportDirectory->NumberOfNames))
        {
            if (!this->RvaToRaw((DWORD)(pFunctionName[ExportFunctionItem.Hint]),&dwRawAddress))
                return FALSE;

            pstrFunctionName=(char*)(this->pBeginOfFile+dwRawAddress);

#if (defined(UNICODE)||defined(_UNICODE))
            CAnsiUnicodeConvert::AnsiToUnicode(pstrFunctionName,&psz);
            _tcsncpy(ExportFunctionItem.FunctionName,psz,MAX_PATH-1);
            free(psz);
#else
            _tcsncpy(ExportFunctionItem.FunctionName,pstrFunctionName,MAX_PATH-1);
#endif
            ExportFunctionItem.FunctionName[MAX_PATH-1]=0;
        }

        if (!bNoOrdinals)
        {
            // get func ordinal
            Ordinal=pFunctionOrdinal[ExportFunctionItem.Hint];
            ExportFunctionItem.ExportedOrdinal=(WORD)(Ordinal+pExportDirectory->Base);
        }

        *ExportFunctionItem.ForwardedName=0;
        // check if func is forwarded
        // forwarded funcs RVA are inside the IMAGE_DIRECTORY_ENTRY_EXPORT DataDirectory
        ExportFunctionItem.Forwarded=((IMAGE_DIRECTORY_ENTRY_EXPORT_StartAddressRVA<=ExportFunctionItem.FunctionAddressRVA)
                    &&(ExportFunctionItem.FunctionAddressRVA<IMAGE_DIRECTORY_ENTRY_EXPORT_EndAddressRVA));

        // if func is forwarded
        if (ExportFunctionItem.Forwarded)
        {
            // get forwarded address
            ForwardedNameAddress=ExportFunctionItem.FunctionAddressRVA;
            if (!this->RvaToRaw(ForwardedNameAddress,&dwRawAddress))
                return FALSE;

            // copy forwarded func
            ForwardedNameAddress=(DWORD)(this->pBeginOfFile+dwRawAddress);
#if (defined(UNICODE)||defined(_UNICODE))
            CAnsiUnicodeConvert::AnsiToUnicode((char*)ForwardedNameAddress,&psz);
            _tcsncpy(ExportFunctionItem.ForwardedName,psz,MAX_PATH-1);
            free(psz);
#else
            _tcsncpy(ExportFunctionItem.ForwardedName,(char*)ForwardedNameAddress,MAX_PATH-1);
#endif
            ExportFunctionItem.ForwardedName[MAX_PATH-1]=0;
        }

        // add item to list
        this->pExportTable->AddItem(&ExportFunctionItem);
    }

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: ParseDelayImportTable
// Object: parse the delay import table. Content of the delay import table is added to 
//              CPE::pImportTable (list of IMPORT_LIBRARY_ITEM)
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::ParseDelayImportTable()
{
    PCImgDelayDescr pDelayDesc;
    DWORD dwRawAddress;
    DWORD dwRVA;
    BOOL bUsingRVA;
    PSTR pszDLLName;
    PIMAGE_THUNK_DATA pThunk;
    PIMAGE_IMPORT_BY_NAME pImportByName;
    DWORD dllNameRVA;
    TCHAR* psz;
    BOOL bOrdinalOnly;
    CPE::IMPORT_LIBRARY_ITEM ImportLibItem;
    CPE::IMPORT_FUNCTION_ITEM ImportFuncItem;
    CPE* pPE;
    BOOL bPEParseSuccess;

    if (this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress==0)
        return TRUE;

    if (!this->RvaToRaw(this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress,&dwRawAddress))
        return FALSE;

    // This code is more complicated than it needs to be, thanks to Microsoft.  When the
    // ImgDelayDescr was originally created for Win32, portability to Win64 wasn't
    // considered.  As such, MS used pointers, rather than RVAs in the data structures.
    // Finally, MS issued a new DELAYIMP.H, which issued a flag indicating whether the
    // field values are RVAs or VAs.  Unfortunately, Microsoft has been rather slow to
    // get this header file out into general distribution.  Currently, you can get it as
    // part of the Win64 headers, or as part of VC7.  In the meanwhile, we'll use some
    // preprocessor trickery so that we can use the new field names, while still compiling
    // with the original DELAYIMP.H.

#if _DELAY_IMP_VER < 2
#define rvaDLLName		szName
#define rvaHmod			phmod
#define rvaIAT			pIAT
#define rvaINT			pINT
#define rvaBoundIAT		pBoundIAT
#define rvaUnloadIAT	pUnloadIAT
#endif

    pDelayDesc = (PCImgDelayDescr)(this->pBeginOfFile+dwRawAddress);
    while ( pDelayDesc->rvaDLLName )
    {
        // from more recent DELAYIMP.H:
        // enum DLAttr {                   // Delay Load Attributes
        //    dlattrRva = 0x1,                // RVAs are used instead of pointers
        //    };
        bUsingRVA = pDelayDesc->grAttrs & 1;

        // get RVA
        if (bUsingRVA)
            // if header use RVA
            dllNameRVA=(DWORD)pDelayDesc->rvaDLLName;
        else
        {
            // else header use VA : convert it to RVA
            if (!this->VaToRva((DWORD)pDelayDesc->rvaDLLName,&dllNameRVA))
                return FALSE;
        }

        // get raw address
        if (!this->RvaToRaw(dllNameRVA, &dwRawAddress))
            return FALSE;
        pszDLLName = (PSTR)(this->pBeginOfFile+dwRawAddress);


#if (defined(UNICODE)||defined(_UNICODE))
        CAnsiUnicodeConvert::AnsiToUnicode(pszDLLName,&psz);
        _tcsncpy(ImportLibItem.LibraryName,psz,MAX_PATH-1);
        free(psz);
#else
        _tcsncpy(ImportLibItem.LibraryName,pszDLLName,MAX_PATH-1);
#endif
        ImportLibItem.LibraryName[MAX_PATH-1]=0;

        // create a list of IMPORT_FUNCTION_ITEM
        ImportLibItem.pFunctions=new CLinkList(sizeof(CPE::IMPORT_FUNCTION_ITEM));

        // add the IMPORT_LIBRARY_ITEM into this->pImportTable
        if(!this->pImportTable->AddItem(&ImportLibItem))
        {
            delete ImportLibItem.pFunctions;
            return FALSE;
        }

        // get the Import Names Table.
        if (bUsingRVA)
            dwRVA=(DWORD)pDelayDesc->rvaINT;
        else
        {
            // convert VA to RVA
            if (!this->VaToRva((DWORD)pDelayDesc->rvaINT,&dwRVA))
                return FALSE;
        }
        // get raw address
        if (!this->RvaToRaw(dwRVA, &dwRawAddress))
            return FALSE;

        pThunk=(PIMAGE_THUNK_DATA)(this->pBeginOfFile+dwRawAddress);

        bOrdinalOnly=FALSE;
        bPEParseSuccess=FALSE;
        pPE=NULL;
        while (pThunk->u1.AddressOfData!=0) // Until there's imported func
        {
            bOrdinalOnly=FALSE;

            // get ordinal value
            ImportFuncItem.Ordinal=(WORD)(pThunk->u1.Ordinal & 0xFFFF);
            
            if ( pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
                bOrdinalOnly=TRUE;
            else
            {
                if (bUsingRVA)
                    dwRVA= pThunk->u1.AddressOfData;
                else
                {   
                    // convert VA to RVA
                    if (!this->VaToRva((DWORD)pThunk->u1.AddressOfData,&dwRVA))
                        return FALSE;
                }
                // get raw address
                if (!this->RvaToRaw(dwRVA, &dwRawAddress))
                    return FALSE;

                pImportByName=(PIMAGE_IMPORT_BY_NAME)(this->pBeginOfFile+dwRawAddress);

                ImportFuncItem.Hint=pImportByName->Hint;
                // check if name is filled
                if (*pImportByName->Name!=0)
                {
#if (defined(UNICODE)||defined(_UNICODE))
                    CAnsiUnicodeConvert::AnsiToUnicode((char*)pImportByName->Name,&psz);
                    _tcsncpy(ImportFuncItem.FunctionName,psz,MAX_PATH-1);
                    free(psz);
#else
                    _tcsncpy(ImportFuncItem.FunctionName,(char*)pImportByName->Name,MAX_PATH-1);
#endif
                    ImportFuncItem.FunctionName[MAX_PATH-1]=0;
                }
                else
                    bOrdinalOnly=TRUE;
            }
            if (bOrdinalOnly)
            {
                *ImportFuncItem.FunctionName=0;
                // try to retrieve name from export table of dll

                if (pPE==NULL)
                {

                    TCHAR pszDirectory[MAX_PATH+1];
                    TCHAR pszFile[MAX_PATH];
                    TCHAR pszPath[MAX_PATH];
                    BOOL bDllFound;
                    
                    // get imported dll filename
                    _tcscpy(pszFile,ImportLibItem.LibraryName);
                    // get directory of current file
                    _tcscpy(pszDirectory,this->pcFilename);
                    psz=_tcsrchr(pszDirectory,'\\');
                    if (psz)
                    {
                        // ends directory
                        psz++;
                        *psz=0;
                    }
                    // if imported dll found
                    if (CDllFinder::FindDll(pszDirectory,pszFile,pszPath))
                    {
                        bDllFound=TRUE;
                        _tcscpy(pszFile,pszPath);

                        // parse export table of the imported dll to get name corresponding to ordinals
                        pPE=new CPE(pszFile);
                        bPEParseSuccess=pPE->Parse(TRUE,FALSE);
                    }
                }

                // if pe parsing success
                if (bPEParseSuccess)
                    this->GetOrdinalImportedFunctionName(ImportFuncItem.Ordinal,pPE,ImportFuncItem.FunctionName);

            }
            // fill the Ordinal only member
            ImportFuncItem.bOrdinalOnly=bOrdinalOnly;

            // add function to ImportLibItem.pFunctions
            if (!ImportLibItem.pFunctions->AddItem(&ImportFuncItem))
            {
                if (pPE)
                    delete pPE;
                return FALSE;
            }

            pThunk++;            // Advance to next thunk
        }

        // free pPE if it has been allocated
        if (pPE)
            delete pPE;

        pDelayDesc++;	// Pointer math.  Advance to next delay import desc.
    }

#if _DELAY_IMP_VER < 2 // Remove the alias names from the namespace
#undef szName
#undef phmod
#undef pIAT
#undef pINT
#undef pBoundIAT
#undef pUnloadIAT
#endif
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: ParseImportTable
// Object: parse the import table. Content of the import table is stored in 
//              CPE::pImportTable (list of IMPORT_LIBRARY_ITEM)
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::ParseImportTable()
{
    // empty import table list
    this->RemoveImportTableItems();

    if (this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress==0)
        // parse delay import table
        return this->ParseDelayImportTable();

    DWORD dwRawAddress;
    IMAGE_IMPORT_DESCRIPTOR* pImportDirectory;
    IMAGE_IMPORT_BY_NAME* pImportByName;
    IMAGE_THUNK_DATA* pThunkData=0;
    CPE::IMPORT_LIBRARY_ITEM ImportLibItem;
    CPE::IMPORT_FUNCTION_ITEM ImportFuncItem;
    DWORD SectionMinRVA;
    DWORD SectionMaxRVA;
    BOOL BadThunkDataPointer;
    CPE* pPE;
    BOOL bPEParseSuccess;
    TCHAR* psz;
    char* pstrLibName;
    
    if (!this->RvaToRaw(this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,&dwRawAddress))
        return FALSE;
    
    pImportDirectory=(IMAGE_IMPORT_DESCRIPTOR*)(this->pBeginOfFile+dwRawAddress);


    if (!this->GetRVASectionLimits(this->NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                             &SectionMinRVA,
                             &SectionMaxRVA))
                             return FALSE;

    // for each imported dll
    for (;;)
    {
        // See if we've reached an empty IMAGE_IMPORT_DESCRIPTOR (no more items)
        if ( (pImportDirectory->TimeDateStamp==0 ) && (pImportDirectory->Name==0) )
            break;

        // get lib name
        if (!this->RvaToRaw(pImportDirectory->Name,&dwRawAddress))
            return FALSE;

        pstrLibName=(char*)this->pBeginOfFile+dwRawAddress;
#if (defined(UNICODE)||defined(_UNICODE))
        CAnsiUnicodeConvert::AnsiToUnicode(pstrLibName,&psz);
        _tcsncpy(ImportLibItem.LibraryName,psz,MAX_PATH-1);
        free(psz);
#else
        _tcsncpy(ImportLibItem.LibraryName,pstrLibName,MAX_PATH-1);
#endif
        ImportLibItem.LibraryName[MAX_PATH-1]=0;

        // create a list of IMPORT_FUNCTION_ITEM
        ImportLibItem.pFunctions=new CLinkList(sizeof(CPE::IMPORT_FUNCTION_ITEM));

        // add the IMPORT_LIBRARY_ITEM into this->pImportTable
        if(!this->pImportTable->AddItem(&ImportLibItem))
        {
            delete ImportLibItem.pFunctions;
            return FALSE;
        }

        BadThunkDataPointer=FALSE;
        // find ThunkData to get function names and ordinals
        if (!this->RvaToRaw(pImportDirectory->FirstThunk,&dwRawAddress))
            BadThunkDataPointer=TRUE;
        else
        {
            // get pThunkData
            pThunkData=(IMAGE_THUNK_DATA*)(this->pBeginOfFile+dwRawAddress);
            if (IsBadReadPtr(pThunkData,sizeof(DWORD)))
                BadThunkDataPointer=TRUE;
            else
            {
		        if ( (*(PDWORD)pThunkData <= SectionMinRVA) || (*(PDWORD)pThunkData >= SectionMaxRVA) )
                    BadThunkDataPointer=TRUE;
            }
        }
        // If the pointer that thunk points to is outside of the 
        // current section, it looks like this file is "pre-fixed up" with regards
		// to the thunk table.  In this situation, we'll need to fall back
		// to the hint-name (aka, the "Characteristics") table.
		if (BadThunkDataPointer )
		{
			if ( pImportDirectory->Characteristics == 0 )
				return FALSE;

            if (!this->RvaToRaw(pImportDirectory->Characteristics,&dwRawAddress))
                return FALSE;
            pThunkData=(IMAGE_THUNK_DATA*)(this->pBeginOfFile+dwRawAddress);
        }

        bPEParseSuccess=FALSE;
        pPE=NULL;
        // for each imported func
        while( pThunkData->u1.AddressOfData != 0)// Until there's imported func
        {

            // if ordinal func only 
			if ( pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                ImportFuncItem.Ordinal=(WORD)(pThunkData->u1.Ordinal & 0xFFFF);
                ImportFuncItem.bOrdinalOnly=TRUE;
                ImportFuncItem.Hint=0xFFFF;
            }
			else
			{
                ImportFuncItem.bOrdinalOnly=FALSE;
                ImportFuncItem.Ordinal=0xFFFF;
                if (!this->RvaToRaw(pThunkData->u1.AddressOfData,&dwRawAddress))
                {
                    if (pPE)
                        delete pPE;
                    return FALSE;
                }
                pImportByName=(IMAGE_IMPORT_BY_NAME*)(this->pBeginOfFile+dwRawAddress);
                ImportFuncItem.Hint=pImportByName->Hint;
                // check if name is filled
                if (*pImportByName->Name!=0)
                {
#if (defined(UNICODE)||defined(_UNICODE))
                    CAnsiUnicodeConvert::AnsiToUnicode((char*)pImportByName->Name,&psz);
                    _tcsncpy(ImportFuncItem.FunctionName,psz,MAX_PATH-1);
                    free(psz);
#else
                    _tcsncpy(ImportFuncItem.FunctionName,(char*)pImportByName->Name,MAX_PATH-1);
#endif
                    ImportFuncItem.FunctionName[MAX_PATH-1]=0;
                }
                else
                    *ImportFuncItem.FunctionName=0;

            }
            if (ImportFuncItem.bOrdinalOnly)
            {
                *ImportFuncItem.FunctionName=0;
                // try to retrieve name from export table of dll

                if (pPE==NULL)
                {

                    TCHAR pszDirectory[MAX_PATH+1];
                    TCHAR pszFile[MAX_PATH];
                    TCHAR pszPath[MAX_PATH];
                    BOOL bDllFound;

                    // get imported dll filename
                    _tcscpy(pszFile,ImportLibItem.LibraryName);
                    // get directory of current file
                    _tcscpy(pszDirectory,this->pcFilename);
                    psz=_tcsrchr(pszDirectory,'\\');
                    if (psz)
                    {
                        // ends directory
                        psz++;
                        *psz=0;
                    }
                    // if imported dll found
                    if (CDllFinder::FindDll(pszDirectory,pszFile,pszPath))
                    {
                        bDllFound=TRUE;
                        _tcscpy(pszFile,pszPath);

                        // parse export table of the imported dll to get name corresponding to ordinals
                        pPE=new CPE(pszFile);
                        bPEParseSuccess=pPE->Parse(TRUE,FALSE);
                    }
                }

                // if pe parsing success
                if (bPEParseSuccess)
                    this->GetOrdinalImportedFunctionName(ImportFuncItem.Ordinal,pPE,ImportFuncItem.FunctionName);
			}

            // add function to ImportLibItem.pFunctions
            if (!ImportLibItem.pFunctions->AddItem(&ImportFuncItem))
            {
                if (pPE)
                    delete pPE;
                return FALSE;
            }

            // go to next IMAGE_THUNK_DATA
            pThunkData++;
        }
        // free pPE if it has been allocated
        if (pPE)
            delete pPE;

        // go to next IMAGE_IMPORT_DESCRIPTOR
        pImportDirectory++;
    }

    // parse delay import table
    return this->ParseDelayImportTable();
}

//-----------------------------------------------------------------------------
// Name: GetOrdinalImportedFunctionName
// Object: Get function name from ordinal 
// Parameters :
//     in  : WORD Ordinal : imported ordinal value
//           TCHAR* DllName : Name of imported dll 
//     out : TCHAR* FunctionName : name of the function. Should be MAX_PATH size at least
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::GetOrdinalImportedFunctionName(WORD Ordinal,TCHAR* DllName,OUT TCHAR* FunctionName)
{
    CPE pe(DllName);
    if (!pe.Parse(TRUE,FALSE))
        return FALSE;

    return this->GetOrdinalImportedFunctionName(Ordinal,&pe,FunctionName);
}

//-----------------------------------------------------------------------------
// Name: GetOrdinalImportedFunctionName
// Object: Get function name from ordinal 
// Parameters :
//     in  : WORD Ordinal
//           CPE* pPe : pointer to the Pe of file containing Export function name and ordinal
//     out : TCHAR* FunctionName : name of the function. Should be MAX_PATH size at least
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::GetOrdinalImportedFunctionName(WORD Ordinal,CPE* pPE,OUT TCHAR* FunctionName)
{
    *FunctionName=0;
    PEXPORT_FUNCTION_ITEM pExportFunction;
    CLinkListItem* pItemLibExport;

    // find function in exported array
    
    pPE->pExportTable->Lock();
    for (pItemLibExport=pPE->pExportTable->Head;pItemLibExport;pItemLibExport=pItemLibExport->NextItem)
    {
        pExportFunction=(PEXPORT_FUNCTION_ITEM)pItemLibExport->ItemData;
        // check if function is found
        if (Ordinal==pExportFunction->ExportedOrdinal)
        {
            if (*pExportFunction->FunctionName==0)
            {
                pPE->pExportTable->Unlock();
                return FALSE;
            }
            _tcscpy(FunctionName,pExportFunction->FunctionName);
            pPE->pExportTable->Unlock();
            return TRUE;
        }
        
    }
    pPE->pExportTable->Unlock();
    return FALSE;
}

//-----------------------------------------------------------------------------
// Name: GetRVASectionLimits
// Object: Get Section limit of KnownRVABelongingToSection RVA address 
// Parameters :
//     in  : DWORD KnownRVABelongingToSection : an RVA belonging to a section
//     out : DWORD* pStart : begin of the section 
//           DWORD* pEnd : end of the section
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::GetRVASectionLimits(DWORD KnownRVABelongingToSection,DWORD* pStart,DWORD* pEnd)
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    if (IsBadWritePtr(pStart,sizeof(DWORD))||IsBadWritePtr(pEnd,sizeof(DWORD)))
        return FALSE;
    for (int cnt=0;cnt<this->NTHeader.FileHeader.NumberOfSections;cnt++)
    {
        if ((this->pSectionHeaders[cnt].VirtualAddress<=KnownRVABelongingToSection)
            && (this->pSectionHeaders[cnt].VirtualAddress+this->pSectionHeaders[cnt].SizeOfRawData>KnownRVABelongingToSection))
        {
            *pStart=this->pSectionHeaders[cnt].VirtualAddress;
            *pEnd=this->pSectionHeaders[cnt].VirtualAddress+this->pSectionHeaders[cnt].SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}
//-----------------------------------------------------------------------------
// Name: SaveIMAGE_DOS_HEADER
// Object: save DosHeader to file
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::SaveIMAGE_DOS_HEADER()
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    HANDLE hFile;
    BOOL bRet=TRUE;
    DWORD dwNbBytesWritten;
    // open file
    hFile = CreateFile(this->pcFilename, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile==INVALID_HANDLE_VALUE)
    {
        CAPIError::ShowLastError();
        return FALSE;
    }
    // write IMAGE_DOS_HEADER
    if (!WriteFile(hFile,&this->DosHeader,sizeof(IMAGE_DOS_HEADER),&dwNbBytesWritten,NULL))
    {
        CAPIError::ShowLastError();
        bRet=FALSE;
    }
    // close file
    CloseHandle(hFile);
    return bRet;
}

//-----------------------------------------------------------------------------
// Name: SaveIMAGE_NT_HEADERS
// Object: save NTHeader to file
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::SaveIMAGE_NT_HEADERS()
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    HANDLE hFile;
    BOOL bRet=TRUE;
    DWORD dwNbBytesWritten;
    // open file
    hFile = CreateFile(this->pcFilename, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile==INVALID_HANDLE_VALUE)
    {
        CAPIError::ShowLastError();
        return FALSE;
    }
    // move to IMAGE_NT_HEADERS start
    SetFilePointer(hFile,this->DosHeader.e_lfanew,0,FILE_CURRENT);
    // write IMAGE_NT_HEADERS
    if (!WriteFile(hFile,&this->NTHeader,sizeof(IMAGE_NT_HEADERS),&dwNbBytesWritten,NULL))
    {
        CAPIError::ShowLastError();
        bRet=FALSE;
    }
    
    // close file
    CloseHandle(hFile);
    return bRet;
}

//-----------------------------------------------------------------------------
// Name: SavePIMAGE_SECTION_HEADER
// Object: save PIMAGE_SECTION_HEADER to file
//         WARNING currently this func don't allow you to change the number of 
//         sections. It's just allow you to modify fields of theses sections.
//         If number of sections is changed you'll probably get an unworking EXE
// Parameters :
//     in  : 
//     out :
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::SavePIMAGE_SECTION_HEADER()
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    HANDLE hFile;
    BOOL bRet=TRUE;
    DWORD dwNbBytesWritten;
    // open file
    hFile = CreateFile(this->pcFilename, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile==INVALID_HANDLE_VALUE)
    {
        CAPIError::ShowLastError();
        return FALSE;
    }
    // move to IMAGE_NT_HEADERS start
    SetFilePointer(hFile,this->DosHeader.e_lfanew+sizeof(IMAGE_NT_HEADERS),0,FILE_CURRENT);

    // write IMAGE_SECTION_HEADER array
    if (!WriteFile(hFile,this->pSectionHeaders,sizeof(IMAGE_SECTION_HEADER)*this->NTHeader.FileHeader.NumberOfSections,&dwNbBytesWritten,NULL))
    {
        CAPIError::ShowLastError();
        bRet=FALSE;
    }
    
    // close file
    CloseHandle(hFile);
    return bRet;
}
//-----------------------------------------------------------------------------
// Name: VaToRva
// Object: Translate virtual address to relative virtual one
// Parameters :
//     in  : DWORD VaAddress
//     out : DWORD* pRvaAddress
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::VaToRva(DWORD VaAddress,DWORD* pRvaAddress)
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    if (IsBadWritePtr(pRvaAddress,sizeof(DWORD)))
        return FALSE;
    *pRvaAddress=VaAddress-this->NTHeader.OptionalHeader.ImageBase;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: RvaToVa
// Object: Translate relative virtual address to virtual one
// Parameters :
//     in  : DWORD RvaAddress
//     out : DWORD* pVaAddress
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::RvaToVa(DWORD RvaAddress,DWORD* pVaAddress)
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    if (IsBadWritePtr(pVaAddress,sizeof(DWORD)))
        return FALSE;
    *pVaAddress=RvaAddress+this->NTHeader.OptionalHeader.ImageBase;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: RawToRva
// Object: Translate raw address to relative virtual one
// Parameters :
//     in  : DWORD RawAddress
//     out : DWORD* pRvaAddress
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::RawToRva(DWORD RawAddress,DWORD* pRvaAddress)
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    if (IsBadWritePtr(pRvaAddress,sizeof(DWORD)))
        return FALSE;
    for (int cnt=0;cnt<this->NTHeader.FileHeader.NumberOfSections;cnt++)
    {
        if ((this->pSectionHeaders[cnt].PointerToRawData<=RawAddress)
            && (this->pSectionHeaders[cnt].PointerToRawData+this->pSectionHeaders[cnt].SizeOfRawData>RawAddress))
        {
            *pRvaAddress=RawAddress-this->pSectionHeaders[cnt].PointerToRawData+this->pSectionHeaders[cnt].VirtualAddress;
            return TRUE;
        }
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Name: RawToRva
// Object: Translate relative virtual address to raw one
// Parameters :
//     in  : DWORD RvaAddress
//     out : DWORD* pRawAddress
//     return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CPE::RvaToRaw(DWORD RvaAddress,DWORD* pRawAddress)
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }

    if (IsBadWritePtr(pRawAddress,sizeof(DWORD)))
        return FALSE;
    for (int cnt=0;cnt<this->NTHeader.FileHeader.NumberOfSections;cnt++)
    {
        if ((this->pSectionHeaders[cnt].VirtualAddress<=RvaAddress)
            && (this->pSectionHeaders[cnt].VirtualAddress+this->pSectionHeaders[cnt].SizeOfRawData>RvaAddress))
        {
            *pRawAddress=RvaAddress-this->pSectionHeaders[cnt].VirtualAddress+this->pSectionHeaders[cnt].PointerToRawData;
            return TRUE;
        }
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Name: GetUnrebasedVirtualAddress
// Object: Translate relative virtual address to raw one
// Parameters :
//     in  : DWORD RebasedRelativeAddress : address in the running process from ImageBase of the module in the running process
//                                          (RebasedRelativeAddress-RebasedImageBase)
//     out : 
//     return : non rebased address on success, -1 on error
//-----------------------------------------------------------------------------
DWORD CPE::GetUnrebasedVirtualAddress(DWORD RebasedRelativeAddress)
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return (DWORD)-1;
    }
    return (DWORD)RebasedRelativeAddress+this->NTHeader.OptionalHeader.ImageBase;
}

//-----------------------------------------------------------------------------
// Name: Is64Bits
// Object: TRUE if 64 bits binary
// Parameters :
//     in  : 
//     out : 
//     return : TRUE if 64 bits
//-----------------------------------------------------------------------------
BOOL CPE::Is64Bits()
{
    if (!this->bNtHeaderParsed)
    {
        if (!this->Parse())
            return FALSE;
    }
    return ( this->NTHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC );
}


//-----------------------------------------------------------------------------
// Name: GetFileName
// Object: get file name of current parsed file
// Parameters :
//     in  : 
//     out : TCHAR* pcFilename : Name of the file being parsed (size should be MAX_PATH in TCHAR)
//     return : 
//-----------------------------------------------------------------------------
void CPE::GetFileName(TCHAR* pszFilename)
{
    _tcscpy(pszFilename, this->pcFilename);
}