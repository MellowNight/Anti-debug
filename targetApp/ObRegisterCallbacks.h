#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define REGISTER_THREAD_CALLBACKS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define REGISTER_PROCESS_CALLBACKS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define UNREGISTER_ALL_CALLBACKS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X803, METHOD_BUFFERED, FILE_ANY_ACCESS)

HANDLE  driverHandle;


struct COMMUNICATION_STRUCT
{
    ULONG   ID;
};



HANDLE  initialize(LPCSTR   registryPath)
{
    HANDLE      newHandle;
    newHandle = CreateFileA(registryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

    return      newHandle;
}



void     protectThread(DWORD    threadID)
{
    COMMUNICATION_STRUCT    myStruct;

    myStruct.ID = threadID;

    DWORD   bytes;

    DeviceIoControl(driverHandle, REGISTER_THREAD_CALLBACKS, &myStruct, sizeof(myStruct), NULL, 0, &bytes, NULL);

    std::cout << "[+] thread " << threadID << " protected by ObRegisterCallbacks!" << std::endl;
}



/*  obregistercallbacks     */

BOOL    protectThreads(DWORD    currentProcessID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return FALSE;


    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        CloseHandle(hThreadSnap);   
        return(FALSE);
    }


    do
    {
        if (te32.th32OwnerProcessID == currentProcessID)
        {
            protectThread(te32.th32ThreadID);
            
        }
    } while (Thread32Next(hThreadSnap, &te32));


    CloseHandle(hThreadSnap);
    
    return TRUE;
}




/*  obregistercallbacks     */

void    protectProcess(DWORD    processID)
{
    COMMUNICATION_STRUCT    myStruct;

    myStruct.ID = processID;

    DWORD   bytes;

    DeviceIoControl(driverHandle, REGISTER_PROCESS_CALLBACKS, &myStruct, sizeof(myStruct), NULL, 0, &bytes, NULL);

    std::cout << "[+] process " << std::dec << processID << "  protected by ObRegisterCallbacks \n";
}


void    unregisterCallbacks()
{

    DWORD   bytes;

    COMMUNICATION_STRUCT input;

    input.ID = 000;

    BOOL    success = DeviceIoControl(driverHandle, UNREGISTER_ALL_CALLBACKS, &input, sizeof(input), NULL, 0, &bytes, NULL);

    if (!success)
    {
        std::cout << "getlastError " << std::dec << GetLastError() << " \n";
    }
}