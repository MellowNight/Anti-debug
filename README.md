# Anti-debug
A simple anti debug program (with kernel mode callbacks)


This protected program uses:

- Heap flags
- ObRegisterCallbacks
- IsDebuggerPresent()
- NtQueryInformationProcess()
- TLS callbacks

