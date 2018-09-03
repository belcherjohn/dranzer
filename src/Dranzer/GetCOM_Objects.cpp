#include "stdafx.h"
#include "GetCOM_Objects.h" 

HKEY OpenCOM_ObjectList(_Out_opt_ DWORD *NumObjects)
{
	if (NumObjects)
		*NumObjects = 0;

	HKEY hKey;
	auto RetVal = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Classes\\CLSID", 0, KEY_READ, &hKey);
	if (RetVal != ERROR_SUCCESS)
		return nullptr;

	if (NumObjects)
	{
		RetVal = ::RegQueryInfoKeyA(hKey, nullptr, nullptr, nullptr, NumObjects,
			nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
		if (RetVal != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return nullptr;
		}
	}

	return hKey;
}

void CloseCOM_ObjectList(HKEY hKey)
{
	::RegCloseKey(hKey);
}

BOOL GetCOM_ObjectInfo(HKEY hKey, DWORD Index, _Out_ COM_ObjectInfoType *COM_Info)
{
	if (COM_Info == nullptr)
		return false;
	COM_Info->CLSID_Str_Wide[0] = 0;
	COM_Info->CLSID_Description[0] = 0;

	wchar_t SubKeyName[100];
	DWORD SubKeyName_Length = _countof(SubKeyName);
	if (::RegEnumKeyExW(hKey, Index, SubKeyName, &SubKeyName_Length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
		return false;

	if (wcscmp(SubKeyName, L"CLSID") == 0)
		return false;

	return GetCOM_ObjectInfo(SubKeyName, COM_Info);
}

BOOL GetCOM_ObjectInfo(PWSTR CLSID_String, _Out_ COM_ObjectInfoType *COM_Info)
{
	if (COM_Info == nullptr)
		return false;
	COM_Info->CLSID_Str_Wide[0] = 0;
	COM_Info->CLSID_Description[0] = 0;

	// Convert to CLSID...
	CLSID clsid;
	if (::CLSIDFromString(CLSID_String, &clsid) != NOERROR)
		return false;

	// Convert back to CLSID string (could have been ProgID)...
	if (StringFromGUID2(clsid, COM_Info->CLSID_Str_Wide, _countof(COM_Info->CLSID_Str_Wide)) == 0)
		return false;

	// Get description...
	char subkey[100];
	sprintf_s(subkey, "Software\\Classes\\CLSID\\%ls", COM_Info->CLSID_Str_Wide);
	DWORD length = sizeof(COM_Info->CLSID_Description);
	if (::RegGetValueA(HKEY_LOCAL_MACHINE, subkey, "", RRF_RT_REG_SZ,
		nullptr, COM_Info->CLSID_Description, &length) != ERROR_SUCCESS)
	{
		COM_Info->CLSID_Description[0] = '\0';
	}

	if (!COM_Info->CLSID_Description[0])
		strcpy_s(COM_Info->CLSID_Description, "[DESCRIPTION NOT AVAILABLE]");

	return true;
}
