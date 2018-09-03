#include "stdafx.h"

#include "TestErrors.h"

const PCSTR ErrorList[] = {
	"User Abort",                                /*  -8  */
	"CreateProcess Failed",                      /*  -7  */
	"CoInitialize failed",                       /*  -6  */
	"Buffer Overrun Fault",                      /*  -5  */
	"COM Object Exception Occurred",             /*  -4  */
	"Can't Create Test Results File",            /*  -3  */
	"COM IObjectSafety Set Interface Opt Fault", /*  -2  */
	"COM Object Operation Hung",                 /*  -1  */
	"SUCCESS",                                   /*   0  */
	"Bag Argument Count",                        /*   1  */
	"Null Pointer Error",                        /*   2  */
	"Buffer Overrun Fault crt Generated",        /*   3  */
	"MultibyteToWideChar Op Failed",             /*   4  */
	"CLSID From String Failed",                  /*   5  */
	"RegOpenKey - CLSID String Failed",          /*   6  */
	"StringFromCLSID Failed"                     /*   7  */
	"COM Object Not Script Safe",                /*   8  */
	"QueryInterface for IDispatchEx Failed",     /*   9  */
	"QueryInterface for IDispatch Failed",       /*  10  */
	"GetTypeInfo Failed",                        /*  11  */
	"Max Recursive Level Reached",               /*  12  */
	"GetDocumentation Failed",                   /*  13  */
	"Append File Failed"                         /*  14  */
};

/*
============================================================
|                     Error_String()                       |
|----------------------------------------------------------|
| Params : Error Number                                    |
| Desc   : Returns a pointer to a character string         |
|          describing the the error input.                 |
|                                                          |
| Returns:  NULL on failure.                               |
|==========================================================|
*/
PCSTR ErrorString(int Error)
{
	if ((DWORD)Error == 0xc0000005)
		return ("Access violation");
	const int idx = Error - ERROR_MIN;
	if (0 <= idx && idx < _countof(ErrorList))
		return ErrorList[idx];
	return ("[Unknown Error]");
}
