#include "register_callbacks.h"

#define REGISTER_THREAD_CALLBACKS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define REGISTER_PROCESS_CALLBACKS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define UNREGISTER_ALL_CALLBACKS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X803, METHOD_BUFFERED, FILE_ANY_ACCESS)


UNICODE_STRING		deviceName;
UNICODE_STRING		symLinkName;

/*
isdebuggerpresent
heap flags
obregistercallbacks
tls callbacks
breakpoint scanning
ntqueryinformationprocess
*/


NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("driver unload\n");

	callbackManager.unregisterCallbacks();
	IoDeleteSymbolicLink(&symLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);

	return STATUS_SUCCESS;
}



NTSTATUS DeviceControlHandler(DEVICE_OBJECT* DeviceObject, PIRP	 Irp)
{
	PIO_STACK_LOCATION		currentStackLocation  =	 IoGetCurrentIrpStackLocation(Irp);
	PCOMMUNICATION_STRUCT	systemBuffer = (PCOMMUNICATION_STRUCT)Irp->AssociatedIrp.SystemBuffer;

	
	/*	register callback for object ID		*/

	switch (currentStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case	REGISTER_THREAD_CALLBACKS:

		/*	ID changes based on if its thread or process	*/

		protectThread(systemBuffer->ID);	
		Irp->IoStatus.Status = STATUS_SUCCESS;

		break;

	case	REGISTER_PROCESS_CALLBACKS:

		protectProcess(systemBuffer->ID);
		Irp->IoStatus.Status = STATUS_SUCCESS;

		break;

	case	 UNREGISTER_ALL_CALLBACKS:
		
		callbackManager.unregisterCallbacks();

		break;

	default:

		DbgPrint("unsupported control code\n");
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		break;
	}



	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS CreateHandler(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	DbgPrint("create request\n");
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS CloseHandler(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	DbgPrint("close request \n");
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}




NTSTATUS	driverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	DbgPrint("driver load \n");
		


	NTSTATUS			status;
	PDEVICE_OBJECT		myDeviceObject;

	callbackManager.initialize_callbacks();

	RtlInitUnicodeString(&deviceName, L"\\Device\\antiDebugDevice");
	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\antiDebugDevice");

	PKLDR_DATA_TABLE_ENTRY	driverSection = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	driverSection->Flags |= 0x20;


	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &myDeviceObject);


	status = IoCreateSymbolicLink(&symLinkName, &deviceName);


	DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;


	
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;
	DriverObject->MajorFunction[IRP_MJ_CREATE] =	CreateHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]  =	CloseHandler;

	ClearFlag(myDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	return STATUS_SUCCESS;
}
