/*
Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>
Dynamic aspect ratio code Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>

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
// Object: provides a Link list
//-----------------------------------------------------------------------------

#pragma once
#include "linklistbase.h"


class CLinkList:public CLinkListBase
{
protected:
    size_t ItemSize;
public:
    CLinkList(size_t ItemSize);
    ~CLinkList(void);

    CLinkListItem* AddItem();
    CLinkListItem* AddItem(BOOL bUserManagesLock);
    CLinkListItem* AddItem(PVOID PointerToItemData);
    CLinkListItem* AddItem(PVOID PointerToItemData,BOOL bUserManagesLock);
    CLinkListItem* InsertItem(CLinkListItem* PreviousItem);
    CLinkListItem* InsertItem(CLinkListItem* PreviousItem,BOOL bUserManagesLock);
    CLinkListItem* InsertItem(CLinkListItem* PreviousItem,PVOID PointerToItemData);
    CLinkListItem* InsertItem(CLinkListItem* PreviousItem,PVOID PointerToItemData,BOOL bUserManagesLock);
    void RemoveItem(CLinkListItem* Item);
    void RemoveItem(CLinkListItem* Item,BOOL bUserManagesLock);
    void RemoveItemFromItemData(PVOID PointerToItemData);
    void RemoveItemFromItemData(PVOID PointerToItemData,BOOL bUserManagesLock);
    void RemoveAllItems();
    void RemoveAllItems(BOOL bUserManagesLock);

    PVOID ToSecureArray(DWORD* pdwArraySize);

};
