#include "ObRegisterCallbacks.h"
#include <thread>
#include <winternl.h>
#include <intrin.h>

#pragma comment(lib,"ntdll.lib")


volatile bool endProgram = false;


void checkPEB()
{

    PBOOLEAN BeingDebugged = (PBOOLEAN)__readgsqword(0x60) + 2;


    if (*BeingDebugged)
    {
        MessageBox(0, L"Debugger detected!", L"PEB->beingdebugged ", 0);

        endProgram = true;
    }

}


void    checkHeapFlags()
{
    PVOID       PEBpointer = (PVOID)__readgsqword(0x60);

    DWORD64     processHeap = *(PDWORD64)((DWORD64)PEBpointer + 0x30);


    ULONG       heapFlags = *(ULONG*)((DWORD64)processHeap + 0x70);
    ULONG       heapForceFlags = *(ULONG*)((DWORD64)processHeap + 0x74);

    if (heapFlags & ~HEAP_GROWABLE)
    {
        MessageBox(0, L"heap flags didnt set growable: Debugger detected!", L"TEB->PEB->processheap->flags", 0);
        endProgram = true;
        
    }

    if (heapForceFlags != 0)
    {
        MessageBox(0, L"heapForceFlags not equal to zero: Debugger detected!", L"TEB->PEB->processheap->forceflags", 0);
        endProgram = true;
    }
}




void NTAPI TLSEntry(PVOID DllHandle, DWORD dwReason, PVOID)
{

        if (dwReason == DLL_PROCESS_ATTACH)
        {
           MessageBox(0, L"TLS callback called for DLL_PROCESS_ATTACH", L"TLSEntry", 0);
        }


        HANDLE DebugPort = NULL;

        checkPEB();

        if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(HANDLE), NULL) == 0)
        {
            if (DebugPort)
            {
                MessageBox(0, L"NtQueryInformationProcess ProcessDebugPort: Debugger detected!", L"NtQueryInformationProcess ", 0);
                endProgram = true;
            }
        }

        checkHeapFlags();
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback")
#else
#endif

#ifdef _WIN64
#pragma const_seg(".CRT$XLB")
EXTERN_C const
#else
#endif
PIMAGE_TLS_CALLBACK tls_callback = TLSEntry;
#ifdef _WIN64
#pragma const_seg()
#else
#endif //_WIN64





int antiDebugThread()
{
    BOOL     is_debugger_present = FALSE;
    HANDLE   DebugPort = NULL;


    while (endProgram != true)
    {
        is_debugger_present = IsDebuggerPresent();

        checkHeapFlags();


        if   (is_debugger_present != FALSE)
        {
            MessageBoxA(NULL, "isDebuggerPresent()   debugger detected ! ! \n", "security violation", MB_ICONEXCLAMATION);

            endProgram = true;
        }


        if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(HANDLE), NULL) == 0)
        {
            if (DebugPort)
            {
                MessageBox(0, L"NtQueryInformationProcess ProcessDebugPort: Debugger detected!", L"NtQueryInformationProcess ", 0);
                endProgram = true;
            }
        }





        if (endProgram == true)
        {
            break;
        }
    }
    return 0;
}





int main()
{
    driverHandle   =   initialize("\\\\.\\antiDebugDevice");

    std::cout << "driver handle is: " << std::hex << driverHandle << std::endl;
   
    protectProcess(GetCurrentProcessId());


    std::thread     antiDebugLoop(antiDebugThread);

    protectThreads(GetCurrentProcessId());


    int a;
    std::cout << "now try to attach the debugger. \n";

    Sleep(5000);

    std::cout << "enter 3 to exit\n";
    while (1)
    {
        std::cin >> a;

        if (a == 3)
        {
            break;
        }
    }


    endProgram = true;

    antiDebugLoop.join();

    std::cout << "main loop terminated \n";

    unregisterCallbacks();

    CloseHandle(driverHandle);


    while (1)
    {
        std::cin.get();
    }
}

