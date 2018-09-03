// TestAndReport.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"

#include "on_exit_scope.h"
#include "win32_exception.h"
#include "TestErrors.h"

#include <comdef.h>
#pragma comment(lib, "comsuppw.lib")
#include <math.h>
#include <sal.h>

#include <exception>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#define LOG_CRASH_ON_FREE 1

void PrintUsage(PSTR argv[])
{
	std::cerr
		<< "Usage: " << argv[0]
		<< " -c <CLSID> (-t | -g) [-o <outputfile>] \n"
		"Options:\n"
		"        -c <CLSID>        - CLSID. Ex. "
		"'{E37D0378-3E36-403A-9698-B7ECFD77770B}'\n"
		"        -t                - Test COM object.\n"
		"        -g                - Generate interface for COM object.\n"
		"        -o <outputfile>   - Log all output to the given file.\n"
		"        -h                - Display this message.\n";
}

enum class ExecutionMode
{
	None,
	TestControl,
	GenerateInterface,
};

// Forward declarations
std::wstring Widen(PCSTR pStr, int cbStr = -1);
std::wstring Widen(const std::string &str);
std::string Narrow(PCWSTR pStr, int cchStr = -1);
std::string Narrow(const std::wstring &str);
std::string Format(_Printf_format_string_ PCSTR Format, ...);
void LogInfo(_Printf_format_string_ PCSTR Format, ...);
void LogError(_Printf_format_string_ PCSTR Format, ...);

void ParseArguments(int argc, PSTR argv[]);
int TestDispatchInterface(_In_ IDispatch *pIDispatch, bool PrintOnly,
	DWORD Level = 0);

// Global variables
static ExecutionMode gExecutionMode = ExecutionMode::None;
static std::string gCLSIDToTest;
static std::string gLogFileName;
static HANDLE gLogFileHandle = nullptr;
constexpr auto kMaxRecurse = 2;
__declspec(thread) const win32_exception::Installer win32ExceptionHandler;

int main(int argc, PSTR argv[])
{
	ParseArguments(argc, argv);

	if (!gLogFileName.empty())
	{
		// Open log...
		for (auto RetryCount = 0; RetryCount < 5; ++RetryCount)
		{
			if (RetryCount > 0)
				::Sleep(2000);

			gLogFileHandle = ::CreateFileA(gLogFileName.c_str(),  // file to create
				GENERIC_WRITE,         // open for writing
				0,                     // do not share
				nullptr,               // default security
				CREATE_ALWAYS,         //
				FILE_ATTRIBUTE_NORMAL, // normal file
				nullptr);              // no attr. template
		}
		if (!gLogFileHandle)
		{
			LogError("Could not open output file: Error=%u.", ::GetLastError());
			return CANT_CREATE_TEST_RESULTS_FILE;
		}
	}
	ON_EXIT_SCOPE(if (gLogFileHandle)::CloseHandle(gLogFileHandle));

	// Convert gCLSIDToTest to a CLSID...
	CLSID clsid;
	HRESULT hr;
	if (SUCCEEDED(hr = ::CLSIDFromString(Widen(gCLSIDToTest).c_str(), &clsid)))
	{
		// Convert clsid to a CLSID just in case gCLSIDToTest is a ProgID.
		// This should never fail...
		LPOLESTR olesz = nullptr;
		if (FAILED(hr = ::StringFromCLSID(clsid, &olesz)))
		{
			LogError("StringFromCLSID() failed: %s", _com_error(hr).ErrorMessage());
			return CLSID_FROM_STRING_FAILED;
		}
		gCLSIDToTest = Narrow(olesz);
		::CoTaskMemFree(olesz);

	}
	else
	{
		LogError("CLSIDFromString('%s') failed: %s", gCLSIDToTest.c_str(),
			_com_error(hr).ErrorMessage());
		return CLSID_FROM_STRING_FAILED;
	}

	// Get the CLSID description...
	std::string CLSID_Description;
	{
		char subkey[100];
		sprintf_s(subkey, "Software\\Classes\\CLSID\\%hs", gCLSIDToTest.c_str());
		DWORD length = 0;
		auto res = ::RegGetValueA(HKEY_LOCAL_MACHINE, subkey, "", RRF_RT_REG_SZ,
			nullptr, nullptr, &length);
		if (res == ERROR_SUCCESS && length > 0)
		{
			CLSID_Description.resize(length - 1);
			::RegGetValueA(HKEY_LOCAL_MACHINE, subkey, "", RRF_RT_REG_SZ, nullptr,
				&CLSID_Description[0], &length);
		}
	}

	if (gExecutionMode == ExecutionMode::TestControl)
	{
		LogInfo("Testing COM Object - %s %s", gCLSIDToTest.c_str(),
			CLSID_Description.c_str());
	}
	else if (gExecutionMode == ExecutionMode::GenerateInterface)
	{
		LogInfo("Interface for COM Object - %s %s", gCLSIDToTest.c_str(),
			CLSID_Description.c_str());
	}

	if (FAILED(hr = ::CoInitialize(nullptr)))
	{
		LogError("CoInitialize() failed: 0x%08X: %s.", hr,
			_com_error(hr).ErrorMessage());
		return COINITIALIZE_FAILED;
	}
	ON_EXIT_SCOPE(::CoUninitialize());

	IDispatchPtr pIDispatch;
	hr = pIDispatch.CreateInstance(clsid, nullptr,
		CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER);
	if (FAILED(hr))
	{
		LogError("Create instance failed: 0x%08X: %s.", hr,
			_com_error(hr).ErrorMessage());
		return QUERY_INTERFACE_FOR_IDISPATCH_FAILED;
	}

	return TestDispatchInterface(pIDispatch,
		gExecutionMode != ExecutionMode::TestControl);
}

void ParseArguments(int argc, PSTR argv[])
{
	for (auto i = 1; i < argc; ++i)
	{
		const auto arg = argv[i];

		if (strlen(arg) != 2 || !(arg[0] == '-' || arg[0] == '/'))
		{
			LogError("Error in command line: Unexpected value: %s", arg);
			PrintUsage(argv);
			exit(2);
		}

		switch (arg[1])
		{
		case 'c':
			if (!gCLSIDToTest.empty())
			{
				LogError("Invalid command line: -c option can only be used once.");
				PrintUsage(argv);
				exit(2);
			}
			if (i + 1 >= argc)
			{
				LogError(
					"Invalid command line: -c option must be followed by a CLSID.");
				PrintUsage(argv);
				exit(2);
			}
			gCLSIDToTest = argv[i + 1];
			++i;
			break;

		case 'o':
			if (!gLogFileName.empty())
			{
				LogError("Invalid command line: -o option can only be used once.");
				PrintUsage(argv);
				exit(2);
			}
			if (i + 1 >= argc)
			{
				LogError(
					"Invalid command line: -o option must be followed by file path.");
				PrintUsage(argv);
				exit(2);
			}
			gLogFileName = argv[i + 1];
			++i;
			break;

		case 't':
			gExecutionMode = ExecutionMode::TestControl;
			break;

		case 'g':
			gExecutionMode = ExecutionMode::GenerateInterface;
			break;

		case '?':
			PrintUsage(argv);
			exit(2);
			break;

		default:
			LogError("Error in command line: Unknown option: %s", arg);
			PrintUsage(argv);
			exit(2);
			break;
		}
	}

	if (gCLSIDToTest.empty())
	{
		LogError("Error: CLSID not specified.");
		PrintUsage(argv);
		exit(1);
	}
	if (gExecutionMode == ExecutionMode::None)
	{
		LogError("Error: Execution mode not specified.");
		PrintUsage(argv);
		exit(1);
	}
}

std::wstring Widen(PCSTR pStr, int cbStr /*= -1*/)
{
	assert(pStr);
	assert(cbStr >= -1);
	if (cbStr == -1)
		cbStr = strlen(pStr);
	if (cbStr == 0)
		return {};
	const auto cch = ::MultiByteToWideChar(CP_UTF8, 0, pStr, cbStr, nullptr, 0);
	std::wstring str(cch, L'\0');
	if (cch == 0)
	{
		LogError("Error widening string (%u).", ::GetLastError());
		return {};
	}
	::MultiByteToWideChar(CP_UTF8, 0, pStr, cbStr, &str[0], cch);
	assert(::GetLastError() == 0);
	return str;
}
std::wstring Widen(const std::string &str)
{
	return Widen(str.c_str(), static_cast<int>(str.size()));
}

std::string Narrow(PCWSTR pStr, int cchStr /*= -1*/)
{
	assert(pStr);
	assert(cchStr >= -1);
	if (cchStr == -1)
		cchStr = wcslen(pStr);
	if (cchStr == 0)
		return {};
	const auto cb = ::WideCharToMultiByte(CP_UTF8, 0, pStr, cchStr, nullptr, 0,
		nullptr, nullptr);
	if (cb == 0)
	{
		LogError("Error narrowing string (%u).", ::GetLastError());
		return {};
	}
	std::string str(cb, L'\0');
	::WideCharToMultiByte(CP_UTF8, 0, pStr, cchStr, &str[0], cb, nullptr,
		nullptr);
	assert(::GetLastError() == 0);
	return str;
}
std::string Narrow(const std::wstring &str)
{
	return Narrow(str.c_str(), static_cast<int>(str.size()));
}

std::string FormatV(_Printf_format_string_ PCSTR Format, va_list va)
{
	// The following code optimistically assumes most values will fit in the fixed
	// buffer.
	char fixed[1024];
	auto len = _vsnprintf_s(fixed, _TRUNCATE, Format, va);
	if (len >= 0)
		return std::string(fixed, len);

	// Truncated. Calculate the required size....
	len = vsnprintf(nullptr, 0, Format, va);
	if (len < 0)
		return "<format error>";
	std::string str(len, '\0');
	vsprintf_s(&str[0], str.size() + 1, Format, va);
	return str;
}

std::string Format(_Printf_format_string_ PCSTR Format, ...)
{
	va_list va;
	va_start(va, Format);
	auto str = FormatV(Format, va);
	va_end(va);
	return str;
}

void Log(PCSTR text, size_t length = -1)
{
	if (text && length == -1)
		length = strlen(text);
	if (!text || length == 0)
		return;

	// Always write to stdout
	std::cout.write(text, length);

	// Write to log file
	if (gLogFileHandle)
	{
		do
		{
			DWORD BytesWritten;
			if (!::WriteFile(gLogFileHandle, text, length, &BytesWritten, 0))
				break;
			text += BytesWritten;
			length -= BytesWritten;
		} while (length > 0);
	}
}
void Log(const std::string &text) { Log(text.c_str(), text.size()); }

void LogInfo(_Printf_format_string_ PCSTR Format, ...)
{
	va_list va;
	va_start(va, Format);
	const auto str = FormatV(Format, va);
	va_end(va);
	Log(str);
	Log("\n");
}

void LogError(_Printf_format_string_ PCSTR Format, ...)
{
	va_list va;
	va_start(va, Format);
	const auto str = FormatV(Format, va);
	va_end(va);
	Log("ERROR: ");
	Log(str);
	Log("\n");
}

std::string VariantToString(const VARIANT &var, bool includeVT /*= true*/,
	size_t maxValueLength /*= 0*/)
{
	const auto vt = (var.vt & ~VT_BYREF);
	const auto isref = (var.vt & VT_BYREF) == VT_BYREF;
	auto isptr = isref;
	PCSTR type = nullptr;
	PCWSTR value = nullptr;

#undef CASE_VT
#define CASE_VT(vt)                                                            \
  case vt:                                                                     \
    type = (isref ? #vt "|VT_BYREF:" : #vt ":")
	switch (vt)
	{
		CASE_VT(VT_I1);
		break;
		CASE_VT(VT_I2);
		break;
		CASE_VT(VT_I4);
		break;
		CASE_VT(VT_I8);
		break;
		CASE_VT(VT_R4);
		break;
		CASE_VT(VT_R8);
		break;
		CASE_VT(VT_CY);
		break;
		CASE_VT(VT_DATE);
		break;
		CASE_VT(VT_BSTR);
		break;
		CASE_VT(VT_ERROR);
		break;
		CASE_VT(VT_BOOL);
		break;
		CASE_VT(VT_DECIMAL);
		break;
		CASE_VT(VT_UI1);
		break;
		CASE_VT(VT_UI2);
		break;
		CASE_VT(VT_UI4);
		break;
		CASE_VT(VT_UI8);
		break;
		CASE_VT(VT_INT);
		break;
		CASE_VT(VT_UINT);
		break;
		CASE_VT(VT_VARIANT);
		break;
		CASE_VT(VT_UNKNOWN);
		value = L"{...}";
		isptr = true;
		break;
		CASE_VT(VT_DISPATCH);
		value = L"{...}";
		isptr = true;
		break;
		CASE_VT(VT_ARRAY);
		value = L"[...]";
		isptr = true;
		break;
		CASE_VT(VT_RECORD);
		value = L"{...}";
		isptr = true;
		break;
		CASE_VT(VT_NULL);
		value = includeVT ? L"" : L"Null";
		break;
		CASE_VT(VT_EMPTY);
		value = includeVT ? L"" : L"empty";
		break;
	default:
		return "<UNEXPECTED>";
	}

	if (isptr && var.byref == nullptr)
		value = L"null";

	_bstr_t converted;
	if (!value)
	{
		// try to convert to a bstr
		try
		{
			value = converted = var;
		}
		catch (...)
		{
		}
		if (!value)
			value = L"<???>";
	}

	const auto format = (vt == VT_BSTR ? "%s\"%.*ls%s\"" : "%s%.*ls%s");
	const auto prefix = (includeVT ? type : "");
	auto precision = -1; // all
	auto suffix = "";
	if (0 < maxValueLength && maxValueLength < wcslen(value))
	{
		precision = (maxValueLength <= 3 ? 1 : maxValueLength - 3);
		suffix = "...";
	}
	return Format(format, prefix, precision, value, suffix);
}

void GenerateArgument(_In_ ITypeInfo *pTypeInfo, const TYPEDESC &tdesc,
	_Inout_ VARIANT &arg,
	_Inout_opt_ VARIANT *refValue = nullptr)
{
	::VariantClear(&arg);
	if (refValue)
		::VariantClear(refValue);

	if (tdesc.vt == VT_PTR)
	{
		if (refValue)
		{
			// Make a value reference...
			GenerateArgument(pTypeInfo, *tdesc.lptdesc, *refValue);
			arg.vt = VT_BYREF | refValue->vt;
			arg.byref = refValue->vt == VT_DECIMAL ? (void *)&refValue->decVal
				: (void *)&refValue->lVal;
		}
		else
		{
			// Make a null reference...
			// Call GenerateArgument() to get the correct type.
			_variant_t dummy;
			GenerateArgument(pTypeInfo, *tdesc.lptdesc, dummy);
			arg.vt = VT_BYREF | dummy.vt;
			arg.byref = nullptr; // do not ref dummy
		}
		return;
	}

	// Init to a (potentially) invalid value...
	arg.vt = tdesc.vt;
	switch (tdesc.vt)
	{
	case VT_I1:
		arg.cVal = -1;
		break;
	case VT_I2:
		arg.iVal = -1;
		break;
	case VT_I4:
		arg.lVal = -1L;
		break;
	case VT_I8:
		arg.llVal = -1LL;
		break;
	case VT_R4:
		arg.fltVal = NAN;
		break;
	case VT_R8:
		arg.dblVal = NAN;
		break;
	case VT_CY:
		arg.cyVal.int64 = -1LL;
		break;
	case VT_DATE:
		arg.date = -9999999999999999999999.99999999;
		break;
	case VT_HRESULT: //[[fallthrough]]
	case VT_ERROR:
		arg.scode = static_cast<HRESULT>(-1L);
		break;
	case VT_BOOL:
		arg.boolVal = 10000;
		break;
	case VT_DECIMAL:
		arg.decVal.Lo64 = ~0ULL;
		arg.decVal.Hi32 = ~0UL;
		arg.decVal.sign = DECIMAL_NEG;
		arg.decVal.scale = 0;
		break; // MIN_DECIMAL
	case VT_UI1:
		arg.bVal = 0xFF;
		break;
	case VT_UI2:
		arg.uiVal = 0xFFFF;
		break;
	case VT_UI4:
		arg.ulVal = ~0UL;
		break;
	case VT_UI8:
		arg.ullVal = ~0ULL;
		break;
	case VT_INT:
		arg.intVal = -1;
		break;
	case VT_UINT:
		arg.uintVal = ~0U;
		break;
	case VT_VARIANT:
		arg.pvarVal = nullptr;
		break;
	case VT_DISPATCH:
		arg.pdispVal = nullptr;
		break;
	case VT_UNKNOWN:
		arg.punkVal = nullptr;
		break;
	case VT_BSTR:
	{
		// create a long BSTR
		constexpr auto kBstrChar = 'x';
		constexpr auto kBstrLen = 1024 * 10 - 1;
		arg.bstrVal = ::SysAllocStringLen(nullptr, kBstrLen);
		if (!arg.bstrVal)
			throw std::bad_alloc();
		wmemset(arg.bstrVal, kBstrChar, kBstrLen);
		break;
	}
	case VT_SAFEARRAY:
	{
		// create empty SAFEARRAY
		std::vector<SAFEARRAYBOUND> bounds(tdesc.lpadesc->rgbounds,
			tdesc.lpadesc->rgbounds +
			tdesc.lpadesc->cDims);
		for (auto &bound : bounds)
			bound.cElements = 0;
		arg.parray = ::SafeArrayCreate(tdesc.lpadesc->tdescElem.vt, bounds.size(),
			bounds.data());
		arg.vt = VT_ARRAY;
		break;
	}
	case VT_USERDEFINED:
	{
		// assume it is an enumeration value
		arg.vt = VT_I4;
		arg.lVal = 0;
		break;
	}

	// The remainder are not supported by variant
	case VT_VOID:     //[[fallthrough]]
	case VT_CARRAY:   //[[fallthrough]]
	case VT_INT_PTR:  //[[fallthrough]]
	case VT_UINT_PTR: //[[fallthrough]]
	case VT_LPSTR:    //[[fallthrough]]
	case VT_LPWSTR:
		arg.vt = VT_NULL;
		break;
	default:
		arg.vt = VT_EMPTY;
		break;
	}
}

std::string TypeDescriptionToString(_In_ const TYPEDESC *typeDesc,
	_In_ ITypeInfo *pTypeInfo)
{
	switch (typeDesc->vt)
	{
	default:
		return "<unknown>";
	case VT_I1:
		return "CHAR";
	case VT_I2:
		return "SHORT";
	case VT_I4:
		return "LONG";
	case VT_I8:
		return "LONGLONG";
	case VT_R4:
		return "FLOAT";
	case VT_R8:
		return "DOUBLE";
	case VT_CY:
		return "CY";
	case VT_DATE:
		return "DATE";
	case VT_BSTR:
		return "BSTR";
	case VT_DISPATCH:
		return "IDispatch*";
	case VT_ERROR:
		return "SCODE";
	case VT_BOOL:
		return "VARIANT_BOOL";
	case VT_VARIANT:
		return "VARIANT*";
	case VT_UNKNOWN:
		return "IUnknown*";
	case VT_DECIMAL:
		return "DECIMAL";
	case VT_UI1:
		return "BYTE";
	case VT_UI2:
		return "USHORT";
	case VT_UI4:
		return "ULONG";
	case VT_UI8:
		return "ULONGLONG";
	case VT_INT:
		return "INT";
	case VT_INT_PTR:
		return "INT*";
	case VT_UINT:
		return "UINT";
	case VT_UINT_PTR:
		return "UINT*";
	case VT_VOID:
		return "void";
	case VT_HRESULT:
		return "HRESULT";
	case VT_LPSTR:
		return "char*";
	case VT_LPWSTR:
		return "wchar_t*";
	case VT_PTR:
		return TypeDescriptionToString(typeDesc->lptdesc, pTypeInfo) + "*";
	case VT_SAFEARRAY:
		return "SAFEARRAY(" +
			TypeDescriptionToString(typeDesc->lptdesc, pTypeInfo) + ")";
	case VT_CARRAY:
	{
		std::stringstream stm;
		stm << TypeDescriptionToString(&typeDesc->lpadesc->tdescElem, pTypeInfo);
		for (auto dim = 0u; typeDesc->lpadesc->cDims; ++dim)
		{
			stm << "[";
			if (typeDesc->lpadesc->rgbounds[dim].lLbound != 0)
				stm << typeDesc->lpadesc->rgbounds[dim].lLbound << "+";
			stm << typeDesc->lpadesc->rgbounds[dim].cElements << "]";
		}
		return stm.str();
	}
	case VT_USERDEFINED:
	{
		ITypeInfoPtr pCustTypeInfo;
		if (FAILED(pTypeInfo->GetRefTypeInfo(typeDesc->hreftype, &pCustTypeInfo)))
			return "UnknownCustomType";

		_bstr_t typeName;
		if (FAILED(pCustTypeInfo->GetDocumentation(
			MEMBERID_NIL, typeName.GetAddress(), nullptr, nullptr, nullptr)))
			return "UnknownCustomType";

		return Narrow(typeName);
	}
	}
}

std::string BuildMethodSignature(_In_ ITypeInfo *pTypeInfo,
	_In_ const FUNCDESC *FunctionDescription,
	PCSTR InterfaceName,
	const std::vector<VARIANT> &arguments = {})
{
	_bstr_t methodName;
	if (FAILED(pTypeInfo->GetDocumentation(FunctionDescription->memid,
		methodName.GetAddress(), nullptr,
		nullptr, nullptr)))
		return {};

	std::stringstream MethodInformation;
	const auto returnType = TypeDescriptionToString(
		&FunctionDescription->elemdescFunc.tdesc, pTypeInfo);
	MethodInformation << returnType << " " << InterfaceName
		<< "::" << Narrow(methodName).c_str() << "(";

	if (FunctionDescription->cParams > 0)
	{
		std::vector<BSTR> rgBstrNames(FunctionDescription->cParams + 1, nullptr);
		ON_EXIT_SCOPE(for (auto &s
			: rgBstrNames)
		{
			if (s)
				::SysFreeString(s);
		});

		UINT NumrgBstrNames = 0;
		pTypeInfo->GetNames(FunctionDescription->memid, rgBstrNames.data(),
			FunctionDescription->cParams + 1, &NumrgBstrNames);
		for (auto idx = 0; idx < FunctionDescription->cParams; ++idx)
		{
			const auto elemDesc = FunctionDescription->lprgelemdescParam[idx];

			int attrCount = 0;
			if (elemDesc.paramdesc.wParamFlags & PARAMFLAG_FIN)
				MethodInformation << (attrCount++ == 0 ? "[" : ",") << "in";
			if (elemDesc.paramdesc.wParamFlags & PARAMFLAG_FOUT)
				MethodInformation << (attrCount++ == 0 ? "[" : ",") << "out";
			if (elemDesc.paramdesc.wParamFlags & PARAMFLAG_FRETVAL)
				MethodInformation << (attrCount++ == 0 ? "[" : ",") << "retval";
			if (elemDesc.paramdesc.wParamFlags & PARAMFLAG_FOPT)
				MethodInformation << (attrCount++ == 0 ? "[" : ",") << "opt";
			if (attrCount > 0)
				MethodInformation << "]";

			const auto paramType =
				TypeDescriptionToString(&elemDesc.tdesc, pTypeInfo);
			MethodInformation << paramType;

			if (static_cast<UINT>(idx + 1) < NumrgBstrNames)
			{
				char TempArgStr[41];
				const auto truncated =
					_snprintf_s(TempArgStr, _TRUNCATE, "%ls", rgBstrNames[idx + 1]) < 0;
				MethodInformation << " " << TempArgStr;
				if (truncated)
					MethodInformation << "...";
			}

			if (arguments.size() ==
				static_cast<size_t>(FunctionDescription->cParams))
			{
				// arguments in reverse order...
				const auto argIdx = arguments.size() - idx - 1;
				MethodInformation << "="
					<< VariantToString(arguments[argIdx],
						/*includeVT=*/false,
						/*maxValueLength=*/15);
			}

			if (idx < FunctionDescription->cParams - 1)
				MethodInformation << ", ";
		}
	}

	MethodInformation << ")";
	return MethodInformation.str();
}

int TestMemberFunc(_In_ IDispatch *pIDispatch, bool PrintOnly,
	_In_ ITypeInfo *pTypeInfo,
	const FUNCDESC *FunctionDescription, PCSTR InterfaceName,
	DWORD Level)
{

	std::vector<VARIANT> arguments;
	std::vector<VARIANT> refArgs;

	if (gExecutionMode == ExecutionMode::TestControl)
	{
		// generate arguments...
		arguments.resize(FunctionDescription->cParams);
		refArgs.resize(FunctionDescription->cParams);
		for (auto idx = 0; idx < FunctionDescription->cParams; ++idx)
		{
			// arguments are in reverse order...
			const auto argIdx = arguments.size() - idx - 1;
			::VariantInit(&arguments[argIdx]);
			::VariantInit(&refArgs[argIdx]);

			GenerateArgument(pTypeInfo,
				FunctionDescription->lprgelemdescParam[idx].tdesc,
				arguments[argIdx], &refArgs[argIdx]);
		}
	}

	const auto MethodInformationText = BuildMethodSignature(
		pTypeInfo, FunctionDescription, InterfaceName, arguments);
	if (MethodInformationText.empty())
	{
		LogError("Error getting function signature.");
		return GET_DOCUMENTATION_FAILED;
	}

	PCSTR PropertyType;
	switch (FunctionDescription->invkind)
	{
	case INVOKE_FUNC:
		PropertyType = "Method";
		break;
	case INVOKE_PROPERTYGET:
		PropertyType = "Getter";
		break;
	case INVOKE_PROPERTYPUT:
		PropertyType = "Putter";
		break;
	case INVOKE_PROPERTYPUTREF:
		PropertyType = "PutRef";
		break;
	default:
		LogError("Unexpected function type: %i - %s", FunctionDescription->invkind,
			MethodInformationText.c_str());
		return SUCCESS;
	}

	if (PrintOnly)
	{
		LogInfo("%s: %s", PropertyType, MethodInformationText.c_str());
		return SUCCESS;
	}

	// Invoke method...
	VARIANT returnValue;
	::VariantInit(&returnValue);
	bool COMObjectExceptionOccurred = true;
	try
	{
		DISPPARAMS dispParams = {};
		dispParams.cArgs = arguments.size();
		dispParams.rgvarg = arguments.empty() ? nullptr : arguments.data();
		DISPID dispidPut = DISPID_PROPERTYPUT;
		if (FunctionDescription->invkind == INVOKE_PROPERTYPUT ||
			FunctionDescription->invkind == INVOKE_PROPERTYPUTREF)
		{
			dispParams.rgdispidNamedArgs = &dispidPut;
			dispParams.cNamedArgs = 1;
		}
		UINT dispArgErr = ~0u; // note: arguments are in reverse order relative to
							   // FunctionDescription

		LogInfo("Invoking %s: %s", PropertyType, MethodInformationText.c_str());
		const auto dispRes =
			pTypeInfo->Invoke(pIDispatch, FunctionDescription->memid,
				static_cast<WORD>(FunctionDescription->invkind),
				&dispParams, &returnValue,
				nullptr, //&dispExceptInfo,
				&dispArgErr);

		// Check the dispatch result to make sure we didn't mess up the invocation
		constexpr auto _DISP_E_FIRST = DISP_E_UNKNOWNINTERFACE;
		constexpr auto _DISP_E_LAST = DISP_E_BUFFERTOOSMALL;
		if ((_DISP_E_FIRST <= dispRes && dispRes <= _DISP_E_LAST) &&
			dispRes != DISP_E_EXCEPTION && dispRes != DISP_E_OVERFLOW &&
			dispRes != DISP_E_DIVBYZERO /* &&
				dispRes != DISP_E_BADVARTYPE*/)
		{
			std::string msg;
			if (dispRes == DISP_E_TYPEMISMATCH || dispRes == DISP_E_PARAMNOTFOUND)
			{
				if (dispArgErr < arguments.size())
				{
					msg = Format("%s on argument %u.",
						dispRes == DISP_E_TYPEMISMATCH ? "DISP_E_TYPEMISMATCH"
						: "DISP_E_PARAMNOTFOUND",
						arguments.size() - dispArgErr - 1);
				}
			}

			LogError("Dispatch Error: HRESULT: 0x%08X: %s", dispRes, msg.c_str());
		}
		else
		{
			LogInfo("Result: 0x%08X.", dispRes);
		}

		// Recurse on output interfaces...
		if (SUCCEEDED(dispRes))
		{
			const auto getDispatch = [&](const VARIANT &arg)
			{
				// The value may be garbage, so be prepared...
				IDispatchPtr dispatch;
				try
				{
					IUnknown *unk = nullptr;
					if ((arg.vt & VT_TYPEMASK) == VT_DISPATCH)
						unk = (arg.vt & VT_BYREF) ? arg.ppdispVal ? *arg.ppdispVal : nullptr
						: arg.pdispVal;
					else if ((arg.vt & VT_TYPEMASK) == VT_UNKNOWN)
						unk = (arg.vt & VT_BYREF) ? arg.ppunkVal ? *arg.ppunkVal : nullptr
						: arg.punkVal;
					dispatch = unk;
				}
				catch (const _com_error &)
				{
				}
				catch (const win32_exception &ex)
				{
					UNREFERENCED_PARAMETER(ex);
				}
				return dispatch;
			};

			const auto retValDispatch = getDispatch(returnValue);
			if (retValDispatch && retValDispatch != pIDispatch)
			{
				LogInfo("Recursing on return value:\n"
					"=============================");
				const auto res =
					TestDispatchInterface(retValDispatch, PrintOnly, Level + 1);
				if (res == COM_OBJECT_EXECEPTION_OCCURRED)
					COMObjectExceptionOccurred = true;
				LogInfo("=============================\n"
					"Resuming interface %s.",
					InterfaceName);
			}

			for (auto idx = 0u; idx < arguments.size(); ++idx)
			{
				const auto paramFlags =
					FunctionDescription->lprgelemdescParam[idx].paramdesc.wParamFlags;
				if (!(paramFlags & (PARAMFLAG_FOUT | PARAMFLAG_FRETVAL)))
					continue;

				const auto argDispatch =
					getDispatch(arguments[arguments.size() - idx - 1]);
				if (argDispatch && argDispatch != pIDispatch &&
					argDispatch != retValDispatch)
				{
					LogInfo("Recursing on output argument %d:\n"
						"=============================",
						idx);
					const auto res =
						TestDispatchInterface(argDispatch, PrintOnly, Level + 1);
					if (res == COM_OBJECT_EXECEPTION_OCCURRED)
						COMObjectExceptionOccurred = true;
					LogInfo("=============================\n"
						"Resuming interface %s.",
						InterfaceName);
				}
			}
		}
	}
	catch (const win32_exception &e)
	{
		COMObjectExceptionOccurred = true;
		LogError("Win32 exception while invoking %s: %s:\n"
			"%s",
			PropertyType, MethodInformationText.c_str(), e.what());
	}

	// Release the Return Value
	try
	{
		::VariantClear(&returnValue);
	}
	catch (const win32_exception &e)
	{
#if LOG_CRASH_ON_FREE
		COMObjectExceptionOccurred = true;
		LogError("Win32 exception while invoking ::VariantClear on return value:\n"
			"%s",
			e.what());
#endif
	}

	// Release the arguments
	for (auto idx = 0u; idx < arguments.size(); ++idx)
	{
		try
		{
			::VariantClear(&arguments[arguments.size() - idx - 1]);
			::VariantClear(&refArgs[arguments.size() - idx - 1]);
		}
		catch (const win32_exception &e)
		{
#if LOG_CRASH_ON_FREE
			COMObjectExceptionOccurred = true;
			LogError("Win32 exception while invoking ::VariantClear on argument %u:\n"
				"%s",
				idx, e.what());
#endif
		}
	}

	if (COMObjectExceptionOccurred)
		return COM_OBJECT_EXECEPTION_OCCURRED;
	return SUCCESS;
}

int TestDispatchInterface(_In_ IDispatch *pIDispatch, bool PrintOnly,
	DWORD Level /*= 0*/)
{
	if (Level > kMaxRecurse)
	{
		LogInfo("Reached maximum recursion level (%u).", Level);
		return SUCCESS;
	}

	bool COMObjectExceptionOccurred = false;
	try
	{
		ITypeInfoPtr pTypeInfo;
		TYPEATTR *pTypeAttr = nullptr;
		if (FAILED(pIDispatch->GetTypeInfo(0, 0, &pTypeInfo)) ||
			FAILED(pTypeInfo->GetTypeAttr(&pTypeAttr)))
		{
			LogError("GetTypeInfo Failed.");
			return GET_TYPE_INFO_FAILED;
		}
		ON_EXIT_SCOPE(pTypeInfo->ReleaseTypeAttr(pTypeAttr));

		_bstr_t InterfaceName;
		pTypeInfo->GetDocumentation(MEMBERID_NIL, InterfaceName.GetAddress(),
			nullptr, nullptr, nullptr);

		for (auto idx = 0u; idx < pTypeAttr->cFuncs; ++idx)
		{
			FUNCDESC *FunctionDescription = nullptr;
			const auto hResult = pTypeInfo->GetFuncDesc(idx, &FunctionDescription);
			if (hResult != S_OK)
			{
				if (hResult == E_OUTOFMEMORY)
					LogError("GetFuncDesc Failed (E_OUTOFMEMORY)");
				else if (hResult == E_INVALIDARG)
					LogError("GetFuncDesc Failed (E_INVALIDARG)");
				else
					LogError("GetFuncDesc Failed (0x%08X)", hResult);
				continue;
			}
			ON_EXIT_SCOPE(pTypeInfo->ReleaseFuncDesc(FunctionDescription));

			if (FunctionDescription->wFuncFlags & FUNCFLAG_FRESTRICTED)
				continue; // function not accessible from macro languages.

			const auto res =
				TestMemberFunc(pIDispatch, PrintOnly, pTypeInfo, FunctionDescription,
					Narrow(InterfaceName).c_str(), Level);
			if (res == COM_OBJECT_EXECEPTION_OCCURRED)
				COMObjectExceptionOccurred = true;
		}
	}
	catch (const win32_exception &e)
	{
		COMObjectExceptionOccurred = true;
		LogError("Win32 exception: %s", e.what());
	}

	if (COMObjectExceptionOccurred)
		return COM_OBJECT_EXECEPTION_OCCURRED;
	return SUCCESS;
}
