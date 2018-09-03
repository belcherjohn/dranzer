// Dranzer.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"

#include "GetCOM_Objects.h"
#include "KillApplication.h"
#include "TestErrors.h"
#include "WindowMonitor.h"
#include "on_exit_scope.h"

#include <sal.h>

#include <cassert>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#define RELEASE_VERSION "RELEASE_19"
#define COM_OBJECT_TEST_TIME_LIMIT_IN_SECONDS 80
#if _DEBUG
#define TESTANDREPORT "..//..//TestAndReport//Debug//TestAndReport.exe"
#else
#define TESTANDREPORT "..//..//TestAndReport//Release//TestAndReport.exe"
#endif

static void PrintUsage(PSTR argv[])
{
	std::cout
		<< "Usage: " << argv[0] << " <options> \n"
		<< "Options:\n"
		<< "        -o <outputfile>   - Output Filename\n"
		<< "        -i <inputfile>    - Use input file CLSID list\n"
		<< "        -d <notestfile>   - Use don't test CLSID List\n"
		<< "        -g                - Generate base COM list\n"
		<< "        -l                - Generate Interface Listings\n"
		<< "        -t                - Test Interfaces Properties and Methods\n"
		<< "        -n                - Print COM object information\n";
}

struct less_clsid
{
	bool operator()(const CLSID& a, const CLSID& b) const noexcept
	{
		return &a == &b || memcmp(&a, &b, sizeof(a)) == 0;
	}
};

enum TExecutionMode
{
	NONE,
	GEN_BASE_COM_LIST,
	GEN_INTERFACE_LISTINGS,
	TEST_INTERFACES,
	EMIT_VERSION_INFO,
};

// Forward declarations
std::wstring Widen(PCSTR pStr, int cbStr = -1);
std::wstring Widen(const std::string &str);
std::string Narrow(PCWSTR pStr, int cchStr = -1);
std::string Narrow(const std::wstring &str);
std::string Format(_Printf_format_string_ PCSTR Format, ...);
void LogInfo(_Printf_format_string_ PCSTR Format, ...);
void LogError(_Printf_format_string_ PCSTR Format, ...);

static void ParseArguments(int argc, PSTR argv[]);
static void GenerateComBaseline();
static void EmitVersionInfo();
static int TestCOMObject(COM_ObjectInfoType *COM_ObjectInfo, PCSTR LogFile);
static DWORD WINAPI COM_TestThreadProcRegistry(LPVOID arg);
static DWORD WINAPI COM_TestThreadProcInputFile(LPVOID arg);
static int LogFileContents(PCSTR FileNameToAppend);
static void DeleteTempResultsFile(PCSTR FileName);

TExecutionMode g_ExecutionMode = NONE;
static std::string g_InputFileName;
static std::string g_OutputFileName;
static std::string g_ExcludeFileName;

static HANDLE g_LogFileHandle = nullptr;
static std::set<CLSID, less_clsid> g_ExcludeCLSIDs;
static HANDLE g_TestHarnessKillEvent = nullptr;
static TProcessSnapShot *g_SnapShotOfProcesses = nullptr;
static DWORD g_NumberOfFailedComTests = 0;
static DWORD g_NumberOfHungComObjects = 0;
static DWORD g_NumberOfComObjects = 0;
static DWORD g_NumberOfComObjectsNotSafeForInitialization = 0;
static DWORD g_NumberOfComObjectsWithOutTypeInfo = 0;
static DWORD g_NumberOfComPassTest = 0;
static DWORD g_NumberOfOtherCOM_Errors = 0;

int main(int argc, PSTR argv[])
{
	ParseArguments(argc, argv);

	g_LogFileHandle = nullptr;
	if (!g_OutputFileName.empty())
	{
		g_LogFileHandle = ::CreateFileA(
			g_OutputFileName.c_str(),
			GENERIC_WRITE,         // open for writing
			0,                     // do not share
			nullptr,               // default security
			CREATE_ALWAYS,         //
			FILE_ATTRIBUTE_NORMAL, // normal file
			nullptr);              // no attr. template

		if (g_LogFileHandle == INVALID_HANDLE_VALUE)
		{
			g_LogFileHandle = nullptr;
			LogError("Could not open output file: %u", ::GetLastError());
			exit(2);
		}
	}
	ON_EXIT_SCOPE(if (g_LogFileHandle) ::CloseHandle(g_LogFileHandle));

	if (g_ExecutionMode == GEN_BASE_COM_LIST)
	{
		GenerateComBaseline();
		exit(0);
	}

	if (g_ExecutionMode == EMIT_VERSION_INFO)
	{
		EmitVersionInfo();
		exit(0);
	}

	if (!g_ExcludeFileName.empty())
	{
		std::ifstream NoTestInputFile(g_ExcludeFileName.c_str());
		if (!NoTestInputFile)
		{
			LogError("Can't open no test input file %s", g_ExcludeFileName.c_str());
			exit(1);
		}

		std::string line;
		for (size_t lineNo = 0; NoTestInputFile; ++lineNo)
		{
			//read the next line...
			line.clear();
			line.reserve(1024);
			for (char c; NoTestInputFile.get(c);)
			{
				//break on LF or CR+LF
				if (c == '\r' && NoTestInputFile.peek() == '\n')
					NoTestInputFile.get(c);
				if (c == '\n')
					break;
				line.push_back(c);
			}
			if (line.empty())
				continue;

			CLSID clsid;
			if (::CLSIDFromString(Widen(line).c_str(), &clsid) != NOERROR)
			{
				LogError("Error in 'no test input' file at line %u : %s", lineNo, line.c_str());
				exit(1);
			}
			g_ExcludeCLSIDs.insert(clsid);
		}
	}

	g_TestHarnessKillEvent = ::CreateEventA(nullptr,  // No security attributes
		false, // Manual-reset event
		false, // Initial state is signaled
		nullptr); // Object name
	if (!g_TestHarnessKillEvent)
	{
		LogError("Failed to Create Kill Event Object");
		return (-1);
	}
	ON_EXIT_SCOPE(::CloseHandle(g_TestHarnessKillEvent));

	::SetConsoleCtrlHandler([](DWORD) { return ::SetEvent(g_TestHarnessKillEvent); }, true);

	WindowMonitorStart(true);

	if ((g_SnapShotOfProcesses = GetSnapShotOfProcesses()) == nullptr)
	{
		LogError("Could not get snap shot of running processes.");
		return (-1);
	}
	ON_EXIT_SCOPE(FreeSnapShot(g_SnapShotOfProcesses));

	const auto threadProc = !g_InputFileName.empty()
		? COM_TestThreadProcInputFile
		: COM_TestThreadProcRegistry;
	DWORD id;
	const auto COM_TestThread = ::CreateThread(nullptr, 0, threadProc, nullptr, CREATE_SUSPENDED, &id);
	if (COM_TestThread == nullptr)
	{
		LogError("Failed to create worker thread.");
		return -1;
	}
	::ResumeThread(COM_TestThread);
	::WaitForSingleObject(COM_TestThread, INFINITE);
	::CloseHandle(COM_TestThread);

	WindowMonitorStop();

	// emit test engine version based on svn build revision
	LogInfo("*******************************************************************************");
	LogInfo("Test Engine Version: $Rev: 96 $");

	LogInfo("*******************************************************************************");
	if (g_ExecutionMode == GEN_INTERFACE_LISTINGS)
	{
		LogInfo("Number of COM Objects                       %d", g_NumberOfComObjects);
		LogInfo("Number of COM Objects Listings Generated    %d", g_NumberOfComPassTest);
		LogInfo("Number of COM Objects Listing Failed        %d", g_NumberOfFailedComTests);
		LogInfo("Number of COM Objects Hung During Operation %d", g_NumberOfHungComObjects);
		LogInfo("Number of COM Objects with No Type Info     %d", g_NumberOfComObjectsWithOutTypeInfo);
		LogInfo("Number of COM Objects Misc Errors           %d", g_NumberOfOtherCOM_Errors);
	}
	else
	{
		LogInfo("Number of COM Objects                   %d", g_NumberOfComObjects);
		LogInfo("Number of COM Objects Passed Test       %d", g_NumberOfComPassTest);
		LogInfo("Number of COM Objects Failed Test       %d", g_NumberOfFailedComTests);
		LogInfo("Number of COM Objects Hung During Test  %d", g_NumberOfHungComObjects);
		LogInfo("Number of COM Objects with No Type Info %d", g_NumberOfComObjectsWithOutTypeInfo);
		LogInfo("Number of COM Objects Misc Errors       %d", g_NumberOfOtherCOM_Errors);
	}
	LogInfo("*******************************************************************************");
	return 0;
}

static void ParseArguments(int argc, PSTR argv[])
{
	g_ExecutionMode = NONE;
	g_InputFileName.empty();
	g_OutputFileName.empty();
	g_ExcludeFileName.empty();

	if (argc < 1)
	{
		PrintUsage(argv);
		exit(2);
	}

	// get arguments
	for (int i = 1; i < argc; i++)
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
		case 'i':
			if (i + 1 >= argc)
			{
				LogError(
					"Invalid command line: -i option must be followed by file path.");
				PrintUsage(argv);
				exit(2);
			}
			g_InputFileName = argv[i + 1];
			++i;
			break;

		case 'o':
			if (i + 1 >= argc)
			{
				LogError(
					"Invalid command line: -o option must be followed by file path.");
				PrintUsage(argv);
				exit(2);
			}
			g_OutputFileName = argv[i + 1];
			++i;
			break;

		case 'd':
			if (i + 1 >= argc)
			{
				LogError(
					"Invalid command line: -d option must be followed by file path.");
				PrintUsage(argv);
				exit(2);
			}
			g_ExcludeFileName = argv[i + 1];
			++i;
			break;

		case 'l':
			if (g_ExecutionMode != NONE)
			{
				LogError("Error in command line: -l cannot be used with other execution modes.");
				PrintUsage(argv);
				exit(2);
			}
			g_ExecutionMode = GEN_INTERFACE_LISTINGS;
			break;

		case 'g':
			if (g_ExecutionMode != NONE)
			{
				LogError("Error in command line: -g cannot be used with other execution modes.");
				PrintUsage(argv);
				exit(2);
			}
			g_ExecutionMode = GEN_BASE_COM_LIST;
			break;

		case 't':
			if (g_ExecutionMode != NONE)
			{
				LogError("Error in command line: -t cannot be used with other execution modes.");
				PrintUsage(argv);
				exit(2);
			}
			g_ExecutionMode = TEST_INTERFACES;
			break;

		case 'v':
			if (g_ExecutionMode != NONE)
			{
				LogError("Error in command line: -v cannot be used with other execution modes.");
				PrintUsage(argv);
				exit(2);
			}
			g_ExecutionMode = EMIT_VERSION_INFO;
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

	if (g_ExecutionMode == NONE)
	{
		LogError("Execution mode not specified use -g,-l,-t, or -v.");
		PrintUsage(argv);
		exit(2);
	}
	if ((!g_ExcludeFileName.empty() || !g_InputFileName.empty()) &&
		(g_ExecutionMode == GEN_BASE_COM_LIST ||
			g_ExecutionMode == EMIT_VERSION_INFO))
	{
		LogError("-i,-d options not vaild with -t or -v options.");
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
	if (g_LogFileHandle)
	{
		do
		{
			DWORD BytesWritten;
			if (!::WriteFile(g_LogFileHandle, text, length, &BytesWritten, 0))
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


static void GenerateComBaseline()
{
	DWORD NumObjects;
	const auto hKey = OpenCOM_ObjectList(&NumObjects);
	if (hKey == nullptr)
	{
		std::cout << "ERROR: Can't open COM object database\n";
		return;
	}
	ON_EXIT_SCOPE(CloseCOM_ObjectList(hKey));

	DWORD NumFound = 0;
	for (auto index = 0u; index < NumObjects; index++)
	{
		COM_ObjectInfoType COM_ObjectInfo;
		if (!GetCOM_ObjectInfo(hKey, index, &COM_ObjectInfo))
			continue;

		LogInfo("%ls", COM_ObjectInfo.CLSID_Str_Wide);
		++NumFound;
	}
	std::cout << NumFound << " COM Objects Found\n";
}

static void EmitVersionInfo()
{
	if (RELEASE_VERSION && "$Rev: 96 $")
		LogInfo("Dranzer Release Version: %s; Test Engine Revision: $Rev: 96 $",
			RELEASE_VERSION);
	else
		LogError("Cannot determine version info");
}

static DWORD WINAPI COM_TestThreadProcRegistry(LPVOID /*arg*/)
{
	DWORD NumObjects;
	const auto hKey = OpenCOM_ObjectList(&NumObjects);
	if (hKey == nullptr)
	{
		LogError("Can't open COM object database.");
		return (0);
	}
	ON_EXIT_SCOPE(CloseCOM_ObjectList(hKey));

	for (DWORD index = 0; index < NumObjects; index++)
	{
		const auto WaitResult = ::WaitForSingleObject(g_TestHarnessKillEvent, 0);
		if (WaitResult == WAIT_OBJECT_0)
		{
			LogInfo("*******************************************************************************");
			LogInfo("%s", ErrorString(USER_ABORT));
			LogInfo("*******************************************************************************");
			return (0);
		}

		COM_ObjectInfoType COM_ObjectInfo;
		if (!GetCOM_ObjectInfo(hKey, index, &COM_ObjectInfo))
		{
			// LogError("GetCOM_ObjectInfo Failed for Index %d", index);
			continue;
		}

		CLSID clsid;
		if (::CLSIDFromString(COM_ObjectInfo.CLSID_Str_Wide, &clsid) != NOERROR)
			continue;

		if (g_ExcludeCLSIDs.find(clsid) != g_ExcludeCLSIDs.end())
			continue;

		g_NumberOfComObjects++;

		// Create a temporary file.
		char szTempName[MAX_PATH - 1] = { 0 };
		if (::GetTempPathA(sizeof(szTempName), szTempName) == 0)
		{
			printf("GetTempPath failed with error %d.\n", ::GetLastError());
			return 0;
		}
		strcat_s(szTempName, Narrow(COM_ObjectInfo.CLSID_Str_Wide).c_str());
		strcat_s(szTempName, ".log");
		ON_EXIT_SCOPE(DeleteTempResultsFile(szTempName));

		const auto ExitCode = TestCOMObject(&COM_ObjectInfo, szTempName);
		if (ExitCode > 0)
		{
			if (ExitCode == GET_TYPE_INFO_FAILED)
				g_NumberOfComObjectsWithOutTypeInfo++;
			else
				g_NumberOfOtherCOM_Errors++;
		}
		else if (ExitCode == SUCCESS)
		{
			if (g_ExecutionMode != GEN_INTERFACE_LISTINGS)
				g_NumberOfComPassTest++;
			else
			{
				if (LogFileContents(szTempName) != SUCCESS)
					LogError("Failed to append COM Test Log File");
			}
		}

		if (ExitCode == USER_ABORT)
		{
			LogInfo("*******************************************************************************");
			LogInfo("%s", ErrorString(ExitCode));
			LogInfo("*******************************************************************************");
			return (0);
		}
		if (ExitCode < 0)
		{
			if (ExitCode == COM_OBJECT_OPERATION_HUNG)
				g_NumberOfHungComObjects++;
			else
				g_NumberOfFailedComTests++;

			LogInfo("*******************************************************************************");
			LogInfo("%ls-%s", COM_ObjectInfo.CLSID_Str_Wide, COM_ObjectInfo.CLSID_Description);
			LogInfo("ERROR - %s (0x%x)", ErrorString(ExitCode), ExitCode);
			LogInfo("*******************************************************************************");

			if (LogFileContents(szTempName) != SUCCESS)
				LogError("Failed to append COM Test Log File");
		}
	}
	return (0);
}

static DWORD WINAPI COM_TestThreadProcInputFile(LPVOID /*arg*/)
{
	const auto InputFile = fopen(g_InputFileName.c_str(), "rt");
	if (!InputFile)
	{
		LogError("Can't open input file '%s'", g_InputFileName.c_str());
		exit(1);
	}
	ON_EXIT_SCOPE(fclose(InputFile));

	DWORD LineNumber = 0;
	wchar_t InputLine[1024];
	while (fgetws(InputLine, _countof(InputLine), InputFile))
	{
		++LineNumber;

		if (const auto InputLineLen = wcslen(InputLine))
			if (InputLine[InputLineLen - 1] == '\r')
				InputLine[InputLineLen - 1] = '\0';
		if (!InputLine[0])
			continue;

		const auto WaitResult = ::WaitForSingleObject(g_TestHarnessKillEvent, 0);
		if (WaitResult == WAIT_OBJECT_0)
		{
			LogInfo("*******************************************************************************");
			LogInfo("%s", ErrorString(USER_ABORT));
			LogInfo("*******************************************************************************");
			return (0);
		}

		COM_ObjectInfoType COM_ObjectInfo;
		if (!GetCOM_ObjectInfo(InputLine, &COM_ObjectInfo))
		{
			LogError("Syntax Error in Input Line (%d) - %ls", LineNumber, InputLine);
			return (0);
		}

		CLSID clsid;
		if (::CLSIDFromString(COM_ObjectInfo.CLSID_Str_Wide, &clsid) == NOERROR)
			continue;

		if (g_ExcludeCLSIDs.find(clsid) != g_ExcludeCLSIDs.end())
			continue;

		g_NumberOfComObjects++;

		// Create a temporary file.
		char szTempName[MAX_PATH - 1] = { 0 };
		if (::GetTempPathA(sizeof(szTempName), szTempName) == 0)
		{
			printf("GetTempPath failed with error %d.\n", ::GetLastError());
			return 0;
		}
		strcat_s(szTempName, Narrow(COM_ObjectInfo.CLSID_Str_Wide).c_str());
		strcat_s(szTempName, ".log");
		ON_EXIT_SCOPE(DeleteTempResultsFile(szTempName));

		const auto ExitCode = TestCOMObject(&COM_ObjectInfo, szTempName);
		if (ExitCode > 0)
		{
			if (ExitCode == GET_TYPE_INFO_FAILED)
				g_NumberOfComObjectsWithOutTypeInfo++;
			else
				g_NumberOfOtherCOM_Errors++;
		}
		else if (ExitCode == SUCCESS)
		{
			if (g_ExecutionMode != GEN_INTERFACE_LISTINGS)
				g_NumberOfComPassTest++;
			else
			{
				if (LogFileContents(szTempName) != SUCCESS)
					LogError("Failed to append COM Test Log File");
			}
		}

		if (ExitCode == USER_ABORT)
		{
			LogInfo("*******************************************************************************");
			LogInfo("%s", ErrorString(ExitCode));
			LogInfo("*******************************************************************************");
			return (0);
		}
		if (ExitCode < 0)
		{
			if (ExitCode == COM_OBJECT_OPERATION_HUNG)
				g_NumberOfHungComObjects++;
			else
				g_NumberOfFailedComTests++;

			LogInfo("*******************************************************************************");
			LogInfo("%ls-%s", COM_ObjectInfo.CLSID_Str_Wide, COM_ObjectInfo.CLSID_Description);
			LogInfo("ERROR - %s (0x%x)", ErrorString(ExitCode), ExitCode);
			LogInfo("*******************************************************************************");

			if (LogFileContents(szTempName) != SUCCESS)
				LogError("Failed to append COM Test Log File");
		}
	}
	return (0);
}

static void DeleteTempResultsFile(PCSTR FileName)
{
	for (int RetryCount = 0; RetryCount < 10; ++RetryCount)
	{
		if (RetryCount > 0)
			::Sleep(2000);

		if (::DeleteFileA(FileName))
			break;
		if (::GetLastError() != ERROR_SHARING_VIOLATION)
			break;
	}
}

static int LogFileContents(PCSTR FileNameToAppend)
{
	HANDLE hfile = INVALID_HANDLE_VALUE;
	for (int RetryCount = 0; RetryCount < 5; ++RetryCount)
	{
		if (RetryCount > 0)
			::Sleep(2000);

		hfile = ::CreateFileA(FileNameToAppend,
			GENERIC_READ,          // open for reading
			0,                     // do not share
			nullptr,               // no security
			OPEN_EXISTING,         // existing file only
			FILE_ATTRIBUTE_NORMAL, // normal file
			nullptr);              // no attr. template

		if (hfile != INVALID_HANDLE_VALUE)
			break;
		if (::GetLastError() != ERROR_SHARING_VIOLATION)
			break;
	}
	if (hfile == INVALID_HANDLE_VALUE)
	{
		LogError("Append Open File Failed : %d", ::GetLastError());
		return APPEND_FILE_FAILED;
	}
	ON_EXIT_SCOPE(::CloseHandle(hfile));

	DWORD dwBytesRead;
	BYTE buff[4096];
	while (::ReadFile(hfile, buff, sizeof(buff), &dwBytesRead, nullptr) &&
		dwBytesRead > 0)
	{
		DWORD dwBytesWritten = 0;
		while (dwBytesWritten < dwBytesRead)
		{
			DWORD numWritten;
			if (!::WriteFile(g_LogFileHandle, buff + dwBytesWritten, dwBytesRead - dwBytesWritten, &numWritten, nullptr))
				return APPEND_FILE_FAILED;

			dwBytesWritten += numWritten;
		}
	}
	return SUCCESS;
}

static int TestCOMObject(COM_ObjectInfoType *COM_ObjectInfo, PCSTR LogFile)
{
	char CommandLine[MAX_PATH + 50 + MAX_PATH];
	if (g_ExecutionMode == GEN_INTERFACE_LISTINGS)
		sprintf(CommandLine, "%s -g -c %ls -o %s", TESTANDREPORT, COM_ObjectInfo->CLSID_Str_Wide, LogFile);
	else
		sprintf(CommandLine, "%s -t -c %ls -o %s", TESTANDREPORT, COM_ObjectInfo->CLSID_Str_Wide, LogFile);

	// Start the child process.
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };
	if (!::CreateProcessA(TESTANDREPORT, // module name
		CommandLine,   // Command line.
		nullptr,          // Process handle not inheritable.
		nullptr,          // Thread handle not inheritable.
		FALSE,         // Set handle inheritance to FALSE.
		0,             // No creation flags.
		nullptr,          // Use parent's environment block.
		nullptr,          // Use parent's starting directory.
		&si,           // Pointer to STARTUPINFO structure.
		&pi)           // Pointer to PROCESS_INFORMATION structure.
		)
	{
		LogError("CreateProcess failed (%d).", GetLastError());
		return CREATE_PROCESS_FAILED;
	}

	// Wait until child process exits.
	while(1)
	{
		HANDLE Handles[] = { pi.hProcess, g_TestHarnessKillEvent };
		const auto WaitResult = ::WaitForMultipleObjects(
			_countof(Handles), Handles, false,
			COM_OBJECT_TEST_TIME_LIMIT_IN_SECONDS * 1000);

		if (WaitResult == (WAIT_OBJECT_0 + 1))
		{
			TerminateProcess(pi.hProcess, (UINT)USER_ABORT);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			KillProcessesNotInSnapShot(g_SnapShotOfProcesses);
			return USER_ABORT;
		}

		if (WaitResult == WAIT_TIMEOUT)
		{
			printf("COM Object Hung During Test - Terminating Test Process\n");
			TerminateProcess(pi.hProcess, (UINT)COM_OBJECT_OPERATION_HUNG);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			Sleep(1000);
			KillProcessesNotInSnapShot(g_SnapShotOfProcesses);
			return COM_OBJECT_OPERATION_HUNG;
		}

		break;
	};

	int ExitCode = 0;
	::GetExitCodeProcess(pi.hProcess, (DWORD*)&ExitCode);
	if (ExitCode == BUFFER_OVERRUN_FAULT_CRT_GENERATED)
		ExitCode = BUFFER_OVERRUN_FAULT;
	// printf("exit code = 0x%08X %u\n", ExitCode, ExitCode);

	// Close process and thread handles.
	::CloseHandle(pi.hProcess);
	::CloseHandle(pi.hThread);
	KillProcessesNotInSnapShot(g_SnapShotOfProcesses);
	return ExitCode;
}
