import breaking_bat

print("Script: Execute ROP gadget (local)")
print()

breaking_bat.init_sysapi(ntdll_load_copy=True)
breaking_bat.execute_rop_gadget_local()
