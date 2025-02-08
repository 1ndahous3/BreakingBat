# BreakingBat 🦇

A very flexible tool for testing Windows security solutions and the OS itself.

### Features
- [TODO] The main binary is just an interpreter with special API, the scripts contain the pentest logic
- [TOOD] Passing scripts via file or socket
- [TODO] Interactive mode for live scripting
- [TODO] Build as a DLL to be executed inside another process
- [TODO] Executing pentest scenario stages in different threads
- [TODO] ARM64 Support

### Common pentest scenarios
- Inject an image/shellcode into an existing/new process
- (Shell)code thread injection (existing/new process)
  - Thread injection (InstructionPointer/EntryPoint)
  - APC thread injection (Finding "Alertable" threads/Early Bird with suspended main thread)
  - COM IRundown::DoCallback() injection
  - [TODO] NtSetInformationProcess() + ProcessInstrumentationCallback injection
- Image injection (new process)
  - Process hollowing
  - Process doppelganging
- [TODO] Filesystem read/modification
- [TODO] Disk (sectors) read/modification
- [TODO] Registry read/modification
- [TODO] Runtime anti-EPP/EDR tricks
  - [TODO] Unhooking functions
  - [TODO] AMSI bypass
- [TODO] Local Privilege Escalation
- [TODO] Exploitation of TOCTOU bugs

### Some interesting concepts and techniques
- System modules:
  - Get functions and global data structures in modules (retreive RVA and offsets from PDB symbols)
  - [TODO] Search ROP gadgets in .text section of the image
  - [TODO] Get RW data cave in .data section of the image (up to the end of the page)
- NT API:
  - Most of the system APIs used are functions from **ntdll.dll**, not the **kernel32.dll**/**user32.dll**/... wrappers
  - Ability to load and use a copy of **ntdll.dll**
  - Ability to use alternative API only available in newer versions of Windows (such as `NtMapViewOfSectionEx()`)
  - [TODO] Ability to use direct syscalls
- RPC API:
  - Use COM/RPC wrappers
  - Generate and use RPC interfaces (including undocumented) from IDL files
  - [TODO] Ability to use functions from RPC client libs (**winspool.drv**, ...)
  - [TODO] Ability to use direct calls of `NdrClientCallX()` with RPC interfaces generated from IDL files
  - [TODO] Ability to use direct ALPC calls
- Execute in remote process:
  - Allocate and write shellcode to executable memory
  - [TODO] Execute functions using ROP gadgets in modules

### Acknowledgments

- https://github.com/processhacker/phnt
- https://github.com/gentilkiwi/mimikatz
- https://github.com/hasherezade?tab=repositories