# BreakingBat 🦇

Another tool for pentesting Windows products and the OS itself.

### Features
- [TODO] The main binary is just an interpreter with special API, the scripts contain the pentest logic
- [TOOD] Passing scripts via file or socket
- [TODO] Interactive mode for live scripting
- [TODO] Build as a DLL to be executed inside another process
- [TODO] Executing pentest scenario stages in different threads
- [TODO] ARM64 Support

### Common pentest scenarios
- Inject an image/shellcode into an existing/new process
  - Remote thread injection
  - Process hollowing
- [TODO] Filesystem read/modification
- [TODO] Disk (sectors) read/modification
- [TODO] Registry read/modification
- Runtime anti-EDR tricks
  - Loading and using a copy of **ntdll.dll**
  - [TODO] Unhooking functions
  - [TODO] AMSI bypass
- [TODO] Local Privilege Escalation
- [TODO] Exploitation of TOCTOU bugs

### Some API options
- API from **ntdll.dll**:
  - generic functions (available in **ntdll.lib**)
  - new functions, exported only in newer Windows versions (such as `NtMapViewOfSectionEx()`)
  - [TODO] non-exported functions, called by offset from symbols (via [DIA SDK](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk))
- [TODO] RPC API: functions from RPC client libs (**winspool.drv**, ...)
- [TODO] RPC API: generated RPC stubs + direct call of `NdrClientCallX()`
- [TODO] Execute shellcode from executable memory (outside of module images)
- [TODO] Direct syscalls

### Acknowledgments

- https://github.com/processhacker/phnt
- https://github.com/gentilkiwi/mimikatz
- https://github.com/hasherezade?tab=repositories