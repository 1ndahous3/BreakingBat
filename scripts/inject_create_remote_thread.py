import breaking_bat
from breaking_bat import RemoteProcessOpenMethod, RemoteProcessMemoryMethod

print("Script: Inject via NtCreateThread()")
print()

breaking_bat.init_sysapi(ntdll_load_copy=True)

breaking_bat.set_default_options(
    open_method=RemoteProcessOpenMethod.OpenProcess,
    memory_method=RemoteProcessMemoryMethod.AllocateInAddr
)

breaking_bat.inject_create_remote_thread("notepad.exe")
