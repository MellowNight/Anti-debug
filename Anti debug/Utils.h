
#pragma once

#include "undocumented_structs.h"
#include <intrin.h>


#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ





EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);






PVOID KernelBase;
PVOID KernelSize;
PVOID getKernelBase(OUT PULONG pSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;
	PRTL_PROCESS_MODULES arrayOfModules;
	PVOID routinePtr = NULL; /*RoutinePtr points to a
	routine and checks if it is in Ntoskrnl*/

	UNICODE_STRING routineName;

	if (KernelBase != NULL)
	{
		if (pSize)
			*pSize = (ULONG64)KernelSize;
		return KernelBase;
	}

	RtlInitUnicodeString(&routineName, L"NtOpenFile");
	routinePtr = MmGetSystemRoutineAddress(&routineName); //get address of NtOpenFile


	if (routinePtr == NULL)
	{
		return NULL;
	}
	else
	{

		DbgPrint("MmGetSystemRoutineAddress inside getkernelbase succeed\n");
	}


	//get size of system module information
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
	if (Bytes == 0)
	{
		DbgPrint("%s: Invalid SystemModuleInformation size\n");
		return NULL;
	}


	arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x454E4F45); //array of loaded kernel modules
	RtlZeroMemory(arrayOfModules, Bytes); //clean memory


	Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);
	if (NT_SUCCESS(Status))
	{
		DbgPrint("ZwQuerySystemInformation inside getkernelbase succeed\n");
		PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
		for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
		{

			if (routinePtr >= pMod[i].ImageBase && routinePtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{

				KernelBase = (PVOID)pMod[i].ImageBase;
				KernelSize = (PVOID)pMod[i].ImageSize;

				if (pSize)
					*pSize = (ULONG64)KernelSize;
				break;
			}
		}
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x454E4F45); // 'ENON'

	DbgPrint("KernelSize : %i\n", KernelSize);
	DbgPrint("g_KernelBase : %p\n", KernelBase);
	return (PVOID)KernelBase;
}



PVOID getDriverBaseAddress(OUT PULONG pSize, const char* driverName)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;
	PRTL_PROCESS_MODULES arrayOfModules;


	PVOID			DriverBase = 0;
	ULONG64			DriverSize = 0;


	//get size of system module information
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
	if (Bytes == 0)
	{
		DbgPrint("%s: Invalid SystemModuleInformation size\n");
		return NULL;
	}


	arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x45454545); //array of loaded kernel modules
	RtlZeroMemory(arrayOfModules, Bytes); //clean memory


	Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);

	if (NT_SUCCESS(Status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
		for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
		{
			//list the module names:

			DbgPrint("Image name: %s\n", pMod[i].FullPathName + pMod[i].OffsetToFileName);
			// path name plus some amount of characters will lead to the name itself
			const char* DriverName = (const char*)pMod[i].FullPathName + pMod[i].OffsetToFileName;

			if (strcmp(DriverName, driverName) == 0)
			{
				DbgPrint("found driver\n");


				DriverBase = pMod[i].ImageBase;
				DriverSize = pMod[i].ImageSize;

				DbgPrint("driver module Size : %i\n", DriverSize);
				DbgPrint("Driver module Base : %p\n", DriverBase);


				if (arrayOfModules)
					ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'




				*pSize = DriverSize;
				return DriverBase;
			}
		}
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'



	*pSize = DriverSize;
	return (PVOID)DriverBase;
}



KIRQL disableWP()
{
	KIRQL	tempirql = KeRaiseIrqlToDpcLevel();

	ULONG64  cr0 = __readcr0();

	cr0 &= 0xfffffffffffeffff;

	__writecr0(cr0);

	_disable();

	return tempirql;

}

void enableWP(KIRQL		tempirql)
{
	ULONG64	cr0 = __readcr0();

	cr0 |= 0x10000;

	_enable();

	__writecr0(cr0);

	KeLowerIrql(tempirql);
}


NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}



NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base, BOOLEAN dataOnly)
{

	//ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

	if (NULL == base)
		base = getKernelBase(NULL);
	if (base == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	PVOID ptr = NULL;

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{

		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if ((dataOnly == FALSE) && ((RtlCompareString(&s1, &s2, TRUE) == 0) || (pSection->Characteristics & IMAGE_SCN_CNT_CODE) || (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)))
		{

			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				DbgPrint("found\r\n");
				return status;
			}
			//we continue scanning because there can be multiple sections with the same name.
		}
		else if ((dataOnly == TRUE) && (RtlCompareString(&s1, &s2, TRUE) == 0))
		{
			DbgPrint("valid section\r\n");
			ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				DbgPrint("BBscansection(): found at address: %p ", *(PULONG64)ppFound);
				return status;
			}
			return status;
			//we continue scanning because there can be multiple sections with the same name.
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}