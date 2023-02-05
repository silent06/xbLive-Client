#include "stdafx.h"

void ExceptionToDebug(EXCEPTION_POINTERS* eps, HANDLE hFile) {
	char ExcReason[128] = { 0 }; DWORD writeCount = 0;
	CHAR buffer[256];

	switch (eps->ExceptionRecord->ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to read from or write to a virtual address for which it does not have the appropriate access.");
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to access an array element that is out of bounds and the underlying hardware supports bounds checking.");
		break;
	case EXCEPTION_BREAKPOINT:
		strcpy_s(ExcReason, sizeof(ExcReason), "A breakpoint was encountered.");
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to read or write data that is misaligned on hardware that does not provide alignment.");
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		strcpy_s(ExcReason, sizeof(ExcReason), "One of the operands in a floating-point operation is denormal. A denormal value is one that is too small to represent as a standard floating-point value.");
		break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to divide a floating-point value by a floating-point divisor of zero.");
		break;
	case EXCEPTION_FLT_INEXACT_RESULT:
		strcpy_s(ExcReason, sizeof(ExcReason), "The result of a floating-point operation cannot be represented exactly as a decimal fraction.");
		break;
	case EXCEPTION_FLT_INVALID_OPERATION:
		strcpy_s(ExcReason, sizeof(ExcReason), "This exception represents any floating-point exception not included in this list.");
		break;
	case EXCEPTION_FLT_OVERFLOW:
		strcpy_s(ExcReason, sizeof(ExcReason), "The exponent of a floating-point operation is greater than the magnitude allowed by the corresponding type.");
		break;
	case EXCEPTION_FLT_STACK_CHECK:
		strcpy_s(ExcReason, sizeof(ExcReason), "The stack overflowed or underflowed as the result of a floating-point operation.");
		break;
	case EXCEPTION_FLT_UNDERFLOW:
		strcpy_s(ExcReason, sizeof(ExcReason), "The exponent of a floating-point operation is less than the magnitude allowed by the corresponding type.");
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to execute an invalid instruction.");
		break;
	case EXCEPTION_IN_PAGE_ERROR:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to access a page that was not present, and the system was unable to load the page.");// For example, this exception might occur if a network connection is lost while running a program over the network.");
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to divide an integer value by an integer divisor of zero.");
		break;
	case EXCEPTION_INT_OVERFLOW:
		strcpy_s(ExcReason, sizeof(ExcReason), "The result of an integer operation caused a carry out of the most significant bit of the result.");
		break;
	case EXCEPTION_INVALID_DISPOSITION:
		strcpy_s(ExcReason, sizeof(ExcReason), "An exception handler returned an invalid disposition to the exception dispatcher. Programmers using a high-level language such as C should never encounter this exception.");
		break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to continue execution after a non-continuable exception occurred.");
		break;
	case EXCEPTION_PRIV_INSTRUCTION:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread tried to execute an instruction whose operation is not allowed in the current machine mode.");
		break;
	case EXCEPTION_SINGLE_STEP:
		strcpy_s(ExcReason, sizeof(ExcReason), "A trace trap or other single-instruction mechanism signaled that one instruction has been executed.");
		break;
	case EXCEPTION_STACK_OVERFLOW:
		strcpy_s(ExcReason, sizeof(ExcReason), "The thread used up its stack.");
		break;
	default:
		sprintf_s(ExcReason, sizeof(ExcReason), "Unknown reason %08x.", eps->ExceptionRecord->ExceptionCode);
	}

	sprintf(buffer, "Exception Error has occured:\n\t%s\r\n", ExcReason);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	sprintf(buffer, "\tAddress: 0x%08x\r\n", eps->ExceptionRecord->ExceptionAddress);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	sprintf(buffer, "\tCode   : 0x%08x\r\n", eps->ExceptionRecord->ExceptionCode);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	sprintf(buffer, "\tFlags  : 0x%08x\r\n", eps->ExceptionRecord->ExceptionFlags);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	sprintf(buffer, "\tParameter Count: %d\r\n", eps->ExceptionRecord->NumberParameters);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	if ((eps->ExceptionRecord->NumberParameters > 0) && (eps->ExceptionRecord->NumberParameters < EXCEPTION_MAXIMUM_PARAMETERS))
		for (DWORD x = 0; x < eps->ExceptionRecord->NumberParameters; x++) {
			sprintf(buffer, "\t\tParameter %02d: 0x%08x\r\n", x, eps->ExceptionRecord->ExceptionInformation[x]);
			WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		}

	PCONTEXT pcontx = eps->ContextRecord;
	DWORD contx = pcontx->ContextFlags;
	sprintf(buffer, "\tContext Flags  : 0x%08x\r\n", contx);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	if (contx & CONTEXT_CONTROL) {
		sprintf(buffer, "\tControl Registers:\r\n");
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tMSR: %08x IAR: %08x\r\n", pcontx->Msr, pcontx->Iar);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tLR : %08x CTR: %016I64x\r\n", pcontx->Lr, pcontx->Ctr);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	}
	if (contx & CONTEXT_INTEGER) {
		sprintf(buffer, "\tInteger Registers:\r\n");
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tCR : %08x XER: %08x\r\n", pcontx->Cr, pcontx->Xer);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR 0: %016I64x GPR 1: %016I64x GPR 2: %016I64x\r\n", pcontx->Gpr0, pcontx->Gpr1, pcontx->Gpr2);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR 3: %016I64x GPR 4: %016I64x GPR 5: %016I64x\r\n", pcontx->Gpr3, pcontx->Gpr4, pcontx->Gpr5);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR 6: %016I64x GPR 7: %016I64x GPR 8: %016I64x\r\n", pcontx->Gpr6, pcontx->Gpr7, pcontx->Gpr8);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR 9: %016I64x GPR10: %016I64x GPR11: %016I64x\r\n", pcontx->Gpr9, pcontx->Gpr10, pcontx->Gpr11);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR12: %016I64x GPR13: %016I64x GPR14: %016I64x\r\n", pcontx->Gpr12, pcontx->Gpr13, pcontx->Gpr14);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR15: %016I64x GPR16: %016I64x GPR17: %016I64x\r\n", pcontx->Gpr15, pcontx->Gpr16, pcontx->Gpr17);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR18: %016I64x GPR19: %016I64x GPR20: %016I64x\r\n", pcontx->Gpr18, pcontx->Gpr19, pcontx->Gpr20);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR21: %016I64x GPR22: %016I64x GPR23: %016I64x\r\n", pcontx->Gpr21, pcontx->Gpr22, pcontx->Gpr23);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR24: %016I64x GPR25: %016I64x GPR26: %016I64x\r\n", pcontx->Gpr24, pcontx->Gpr25, pcontx->Gpr26);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR27: %016I64x GPR28: %016I64x GPR29: %016I64x\r\n", pcontx->Gpr27, pcontx->Gpr28, pcontx->Gpr29);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
		sprintf(buffer, "\t\tGPR30: %016I64x GPR31: %016I64x\r\n", pcontx->Gpr30, pcontx->Gpr31);
		WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	}

	sprintf(buffer, "\r\n", pcontx->Gpr30, pcontx->Gpr31);
	WriteFile(hFile, buffer, strlen(buffer), &writeCount, 0);
	LOG_PRINT(buffer);
}

LONG WINAPI Handler(struct _EXCEPTION_POINTERS* lpExceptionInfo) {
	SYSTEMTIME T;
	GetLocalTime(&T);
	string NewLogPath = Utils::sprintfaA("%scrash.%d%02d%02d%02d%02d%02d.log", T.wYear, T.wMonth, T.wDay, T.wHour, T.wMinute, T.wSecond);
	rename(Utils::sprintfaA("%s%s", "xbLive:\\", "Crashlog").c_str(), NewLogPath.c_str());

	LOG_PRINT("[DEBUG] Unhandled exception occured... dumping log");
	NewLogPath.append(".callstack");
	HANDLE hFile = CreateFile(NewLogPath.c_str(), GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, 0, NULL);

	ExceptionToDebug(lpExceptionInfo, hFile);

	XOVERLAPPED overlapped;
	MESSAGEBOX_RESULT mbresult;
	HANDLE hEvent = WSACreateEvent();
	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.hEvent = hEvent;
	memset(&mbresult, 0, sizeof(mbresult));
	LPCWSTR btnOptions[3] = { L"Reboot", L"Go back to Dashboard",L"Try to continue..." };
	XShowMessageBoxUI(XUSER_INDEX_ANY, L"XbLive CRASH", L"XbLive crashed, what would you like to do?", 3, btnOptions, 0, XMB_ERRORICON, &mbresult, &overlapped);
	WaitForSingleObject(hEvent, INFINITE);

	WSAResetEvent(hEvent);

	if (mbresult.dwButtonPressed == 0) {
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}
	else {
		if (mbresult.dwButtonPressed == 1) {
			XLaunchNewImage("flash:\\dash.xex", 0);
		}
		else {
			if (mbresult.dwButtonPressed == 2) {

			}
			else {
				XLaunchNewImage("flash:\\dash.xex", 0);
			}
		}
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

HRESULT CrashHandler::Initialize() {
	::SetUnhandledExceptionFilter(Handler);
	return S_OK;
}