#ifndef _TESTERRORS_H_
#define _TESTERRORS_H_

#include <sal.h>

const int ERROR_MIN = -8;
const int USER_ABORT = -8;
const int CREATE_PROCESS_FAILED = -7;
const int COINITIALIZE_FAILED = -6;
const int BUFFER_OVERRUN_FAULT = -5;
const int COM_OBJECT_EXECEPTION_OCCURRED = -4;
const int CANT_CREATE_TEST_RESULTS_FILE = -3;
const int COM_OBJECTSAFETY_SET_INTERFACE_OPT_FAULT = -2;
const int COM_OBJECT_OPERATION_HUNG = -1;
const int SUCCESS = 0;
const int BAD_ARGUMENT_COUNT = 1;
const int NULL_POINTER_ERROR = 2;
const int BUFFER_OVERRUN_FAULT_CRT_GENERATED = 3;
const int MULTIBYTE_TO_WIDE_CHAR_FAILED = 4;
const int CLSID_FROM_STRING_FAILED = 5;
const int REG_OPEN_KEY_CLSID_CLSID_STRING_FAILED = 6;
const int STRING_FROM_CLSID_FAILED = 7;
const int COM_OBJECT_NOT_SCRIPT_SAFE = 8;
const int QUERY_INTERFACE_FOR_IDISPATCH_EX_FAILED = 9;
const int QUERY_INTERFACE_FOR_IDISPATCH_FAILED = 10;
const int GET_TYPE_INFO_FAILED = 11;
const int MAX_RECURSIVE_LEVEL_REACHED = 12;
const int GET_DOCUMENTATION_FAILED = 13;
const int APPEND_FILE_FAILED = 14;

/*  Returns a pointer to a character string    */
/*  describing the the error input.            */
/*  A pointer is returned if the call succeeds */
/*  NULL is returned if the the error number   */
/*  is invalid.                                */
PCSTR ErrorString(int);

#endif
