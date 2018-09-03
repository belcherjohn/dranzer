#pragma once

#include <wchar.h>
#include <sal.h>

struct COM_ObjectInfoType
{
	WCHAR CLSID_Str_Wide[MAX_PATH];
	TCHAR CLSID_Description[1024];
};

HKEY OpenCOM_ObjectList(_Out_opt_ DWORD *NumObjects);
BOOL GetCOM_ObjectInfo(HKEY  hKey, DWORD Index, _Out_ COM_ObjectInfoType *COM_Info);
BOOL GetCOM_ObjectInfo(PWSTR CLSID_String, _Out_ COM_ObjectInfoType *COM_Info);
void CloseCOM_ObjectList(HKEY hKey);
