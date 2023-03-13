# BreakingBat 🦇
## _Another tool for pentesting Windows products and the OS itself_

### Features
- [TODO] Build as a DLL to be executed inside another process
- [TODO] The main binary is just an interpreter with special API, the scripts contain the pentest logic
- [TOOD] Passing scripts via file or socket
- [TODO] Interactive mode for live scripting

### Common pentest scenarios
- Inject an image/shellcode into an existing/new process
- [TODO] Filesystem read/modification
- [TODO] Registry read/modification
- [TODO] Runtime anti-EDR tricks in own process (unhooking, AMSI bypass, ...)
- [TODO] Local Privilege Escalation
- [TODO] Exploitation of TOCTOU bugs

### Some API options
- [TODO] Usermode WinAPI from various generic libs (**kernel32.dll**, **user32.dll**, ...)
- API from **ntdll.dll**: generic functions (available in **ntdll.lib**)
- API from **ntdll.dll**: new functions, exported only in newer Windows versions (such as `NtMapViewOfSectionEx()`)
- [TODO] RPC API: functions from RPC client libs (**winspool.drv**, ...)
- [TODO] RPC API: generated RPC stubs + direct call of `NdrClientCallX()`
- [TODO] Execute shellcode from executable memory (outside of module images)
- [TODO] Direct syscalls
