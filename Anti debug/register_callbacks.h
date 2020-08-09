#pragma once
#include "undocumented_structs.h"
#include "Utils.h"



typedef struct _COMMUNICATION_STRUCT
{
	ULONG	ID;
}COMMUNICATION_STRUCT, * PCOMMUNICATION_STRUCT;



struct CALLBACK_MANAGER
{
	PVOID	CallbackHandle[12];

	int Index;

	void	 initialize_callbacks()
	{
		for (int i = 0; i < 12; ++i)
		{
			CallbackHandle[i] = NULL;
		}

		Index = 0;
	}

	PVOID*	getHandle(NTSTATUS	externalStatus)
	{
		PVOID* callback = &CallbackHandle[Index];


		/*	if registering callback worked or if callback is already taken then increment index*/

		if (NT_SUCCESS(externalStatus) || (*callback != NULL))
		{
			DbgPrint("new callback reserved \n");

			Index += 1;
		}

		return	callback;
	}

	void	unregisterCallbacks()
	{
		for (int i = 0; i < 12; ++i)
		{
			if (CallbackHandle[i] != NULL)
			{
				DbgPrint("unregistered callback %i !\n", i);
				ObUnRegisterCallbacks(CallbackHandle[i]);
			}
		}
	}
};


CALLBACK_MANAGER	callbackManager;





void	PobPostOperationCallback(
	PVOID RegistrationContext,
	POB_POST_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	return;
}


/*
PAGE:00000000007B8A81                               loc_7B8A81:                             ; CODE XREF: ObRegisterCallbacks+B2CFD↓j
PAGE:00000000007B8A81 BA 20 00 00 00                                mov     edx, 20h ; ' '
PAGE:00000000007B8A86 E8 95 00 BE FF                                call    MmVerifyCallbackFunctionCheckFlags
PAGE:00000000007B8A8B 85 C0                                         test    eax, eax
PAGE:00000000007B8A8D 0F 84 01 2C 0B 00                             jz      loc_86B694      ; patch point
*/





PVOID64		hookPoint;

void	patchObReg()
{
	ULONG size;

	PVOID	ntoskrnlBase = getKernelBase(&size);


	UCHAR pattern[] = { 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x4E, 0x00, 0x48, 0x85, 0xC9, 0x0F, 0x85 };
	BBScanSection("PAGE", pattern, 0x00, 14, &hookPoint, (PVOID64)ntoskrnlBase, FALSE);

	DbgPrint("obregistercallbacks hook point is: %p \n", hookPoint);
	DbgPrint("current byte is: %p \n", *(BYTE*)hookPoint);

	KIRQL	irql = disableWP();

	memset(hookPoint, 0X85, 1);


	enableWP(irql);
}




void	fixObReg()
{

	DbgPrint("current byte is: %p \n", *(BYTE*)hookPoint);

	KIRQL	irql = disableWP();

	memset(hookPoint, 0X84, 1);

	enableWP(irql);
}




/*	function definition from msdn	*/

OB_PREOP_CALLBACK_STATUS	threadCallback(PCOMMUNICATION_STRUCT  registrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PETHREAD	thread = NULL;
	NTSTATUS	status = PsLookupThreadByThreadId((HANDLE)registrationContext->ID, &thread);
	
	PETHREAD	targetThread = (PETHREAD)OperationInformation->Object;


	if (!NT_SUCCESS(status) ||  thread == NULL)
	{
		DbgPrint("our thread not found!!!\n");
		status = STATUS_NOT_FOUND;
	}


	DbgPrint("our thread ID is: %i \n", registrationContext->ID);
	DbgPrint("current thread ID is: %i \n", PsGetThreadId(targetThread));


	if (registrationContext->ID == (ULONG)PsGetThreadId(targetThread))
	{
		DbgPrint("our thread matches requested thread! removing permissions\n");

		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
	}
	return OB_PREOP_SUCCESS;
}





OB_PREOP_CALLBACK_STATUS	 processCallback(PCOMMUNICATION_STRUCT  registrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation)
{

	PEPROCESS	process = NULL;
	NTSTATUS	status = PsLookupProcessByProcessId((HANDLE)registrationContext->ID, &process);


	PEPROCESS	targetProcess = (PEPROCESS)OperationInformation->Object;


	if (!NT_SUCCESS(status) || process == NULL)
	{
		DbgPrint("our process not found!!!\n");
		status = STATUS_NOT_FOUND;
	}


	if ((ULONG)PsGetProcessId(targetProcess) == registrationContext->ID)
	{
		DbgPrint("process callback called! removing handle permissions\n");

		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
	}
	return OB_PREOP_SUCCESS;
}






int		protectThread(int	threadID)
{
	OB_CALLBACK_REGISTRATION		callBackStruct;

	OB_OPERATION_REGISTRATION		callbackOperation;





		
	/*	set up callback operation	*/
	callbackOperation.ObjectType = PsThreadType;

	callbackOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	callbackOperation.PreOperation = (POB_PRE_OPERATION_CALLBACK)threadCallback;

	callbackOperation.PostOperation = PobPostOperationCallback;



	/*	callback altitude	*/
	UNICODE_STRING		 altitude;
	RtlInitUnicodeString(&callBackStruct.Altitude, L"22223");


	callBackStruct.OperationRegistration = &callbackOperation;
	callBackStruct.OperationRegistrationCount = 1;
	callBackStruct.Version = ObGetFilterVersion();
	callBackStruct.RegistrationContext = ExAllocatePool(NonPagedPool, sizeof(COMMUNICATION_STRUCT));
	((PCOMMUNICATION_STRUCT)callBackStruct.RegistrationContext)->ID = threadID;


	
	NTSTATUS	status = ObRegisterCallbacks(&callBackStruct, callbackManager.getHandle(STATUS_SUCCESS));


	if (status == STATUS_ACCESS_DENIED)
	{
		DbgPrint("status access denied! \n");

		patchObReg();

		status = ObRegisterCallbacks(&callBackStruct, callbackManager.getHandle(status));

		fixObReg();
	}


	ULONG	altitudeInt = 22223;


	while (status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
	{

		KIRQL	oldIrql = disableWP();

		altitudeInt += 1;

		RtlZeroMemory(callBackStruct.Altitude.Buffer, callBackStruct.Altitude.Length);


		RtlIntegerToUnicodeString(altitudeInt, 10, &callBackStruct.Altitude);


		status = ObRegisterCallbacks(&callBackStruct, callbackManager.getHandle(status));

		DbgPrint("looking for suitable altitude... current altitude is %wZ \n", &callBackStruct.Altitude);

		enableWP(oldIrql);

		if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
		{
			break;
		}
	}

	

	return 0;
}










int		protectProcess(int	processID)
{
	NTSTATUS	status;

	DbgPrint("protectprocess called !\n");

	OB_CALLBACK_REGISTRATION		callBackStruct;

	OB_OPERATION_REGISTRATION		callbackOperation;






	/*	set up callback operation	*/
	callbackOperation.ObjectType = PsProcessType;

	callbackOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	callbackOperation.PreOperation = (POB_PRE_OPERATION_CALLBACK)processCallback;

	callbackOperation.PostOperation = PobPostOperationCallback;




	/*	callback altitude	*/
	UNICODE_STRING		 altitude;
	RtlInitUnicodeString(&callBackStruct.Altitude, L"22222");



	callBackStruct.OperationRegistration = &callbackOperation;
	callBackStruct.OperationRegistrationCount = 1;
	callBackStruct.Version = ObGetFilterVersion();
	callBackStruct.RegistrationContext = ExAllocatePool(NonPagedPool, sizeof(COMMUNICATION_STRUCT));
	((PCOMMUNICATION_STRUCT)callBackStruct.RegistrationContext)->ID = processID;


	
	status = ObRegisterCallbacks(&callBackStruct, callbackManager.getHandle(STATUS_ACCESS_VIOLATION));

	if (status == STATUS_ACCESS_DENIED)
	{

		DbgPrint("status access denied! \n");

		patchObReg();

		status = ObRegisterCallbacks(&callBackStruct, callbackManager.getHandle(status));

		fixObReg();
	}

	DbgPrint("obregistercallbacks status is: %p \n", status);

	return 0;
}