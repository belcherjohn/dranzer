//
// Copyright 2018 Rockwell Automation Technologies, Inc.
// All Rights Reserved.
//
#pragma once

#include <eh.h>
#include <sal.h>
#include <stdio.h>
#include <windows.h>

#include <stdexcept>
#include <string>

/// \brief Models a Win32 exception (C structured exceptions).
/// \remark You can automatically convert any Win32 exception into
/// win32_exception by creating a win32_exception::Installer instance.
struct win32_exception : std::runtime_error
{
	/// The exception record. May be empty.
	EXCEPTION_RECORD info;

	explicit win32_exception(PCSTR what,
		_In_opt_ const EXCEPTION_RECORD *pinfo = nullptr)
		: std::runtime_error(what), info{ pinfo ? *pinfo : EXCEPTION_RECORD{} } {
		// dont save the nested ExceptionRecord pointer, although we will remember
		// if it existed or not.
		if (info.ExceptionRecord)
			info.ExceptionRecord = (EXCEPTION_RECORD *)~0; // i.e. 0xffffffff
	}
	explicit win32_exception(const std::string &what,
		_In_opt_ const EXCEPTION_RECORD *pinfo = nullptr)
		: win32_exception(what.c_str(), pinfo)
	{
	}

	explicit win32_exception(unsigned int exceptionCode,
		_In_opt_ const EXCEPTION_RECORD *pinfo = nullptr)
		: win32_exception(_build_msg(exceptionCode, pinfo), pinfo)
	{
	}

	/// \brief An RAII class which automatically installs and uninstalls a
	/// translator which converts Win32 exceptions (C structured exceptions) into
	/// win32_exception. \note The translator is \b per-thread, so each thread
	/// must have its own Installer.
	struct Installer
	{
		Installer() : _prev{ _set_se_translator(win32_exception::_convert_se) } {}
		~Installer() { _set_se_translator(_prev); }
		// Not copyable (or movable)
		Installer(const Installer &) = delete;
		Installer &operator=(const Installer &) = delete;

	private:
		const _se_translator_function _prev;
	};

private:
	static std::string _build_msg(unsigned int code,
		_In_opt_ const EXCEPTION_RECORD *info)
	{
		PCSTR exception_name = "Win32 exception";
		PCSTR msg_format = "%s (0x%X) at 0x%p";
		switch (code)
		{
		case EXCEPTION_ACCESS_VIOLATION:
			exception_name = "EXCEPTION_ACCESS_VIOLATION";
			msg_format = "%s (0x%X) at 0x%p: Bad %s at 0x%p";
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			exception_name = "EXCEPTION_DATATYPE_MISALIGNMENT";
			break;
		case EXCEPTION_BREAKPOINT:
			exception_name = "EXCEPTION_BREAKPOINT";
			break;
		case EXCEPTION_SINGLE_STEP:
			exception_name = "EXCEPTION_SINGLE_STEP";
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			exception_name = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			exception_name = "EXCEPTION_FLT_DENORMAL_OPERAND";
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			exception_name = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
			break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			exception_name = "EXCEPTION_FLT_INEXACT_RESULT";
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			exception_name = "EXCEPTION_FLT_INVALID_OPERATION";
			break;
		case EXCEPTION_FLT_OVERFLOW:
			exception_name = "EXCEPTION_FLT_OVERFLOW";
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			exception_name = "EXCEPTION_FLT_STACK_CHECK";
			break;
		case EXCEPTION_FLT_UNDERFLOW:
			exception_name = "EXCEPTION_FLT_UNDERFLOW";
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			exception_name = "EXCEPTION_INT_DIVIDE_BY_ZERO";
			break;
		case EXCEPTION_INT_OVERFLOW:
			exception_name = "EXCEPTION_INT_OVERFLOW";
			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			exception_name = "EXCEPTION_PRIV_INSTRUCTION";
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			exception_name = "EXCEPTION_IN_PAGE_ERROR";
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			exception_name = "EXCEPTION_ILLEGAL_INSTRUCTION";
			break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			exception_name = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
			break;
		case EXCEPTION_STACK_OVERFLOW:
			exception_name = "EXCEPTION_STACK_OVERFLOW";
			break;
		case EXCEPTION_INVALID_DISPOSITION:
			exception_name = "EXCEPTION_INVALID_DISPOSITION";
			break;
		case EXCEPTION_GUARD_PAGE:
			exception_name = "EXCEPTION_GUARD_PAGE";
			break;
		case EXCEPTION_INVALID_HANDLE:
			exception_name = "EXCEPTION_INVALID_HANDLE";
			break;
			// case EXCEPTION_POSSIBLE_DEADLOCK:
			//  exception_name = "EXCEPTION_POSSIBLE_DEADLOCK";
			//  break;
		}

		if (!info)
		{
			return exception_name;
		}

		char msg[256];
		_snprintf_s(msg, _TRUNCATE, msg_format, exception_name, code,
			info->ExceptionAddress,
			info->ExceptionInformation[0] == 1 ? "write" : "read",
			(const void *)info->ExceptionInformation[1]);
		return msg;
	}

	static void __cdecl _convert_se(unsigned int code,
		_In_ EXCEPTION_POINTERS *exception)
	{
		if (code == EXCEPTION_STACK_OVERFLOW)
			throw win32_exception("EXCEPTION_STACK_OVERFLOW",
				exception->ExceptionRecord);
		else
			throw win32_exception(code, exception->ExceptionRecord);
	}
};
