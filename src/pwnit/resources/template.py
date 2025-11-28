from pwn import *

use_patched = False
binary_name = "<exe_relpath:EXE_PATH>" if (not use_patched) else "<exe_debug_relpath:EXE_DEBUG_PATH>"
exe  = ELF(binary_name, checksec=True)
libc = ELF("<libc_relpath:LIBC_PATH>", checksec=False)
context.binary = exe

ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)

if args.REMOTE:
	io = connect("<host:HOST>", "<port:PORT>")
elif args.GDB:
	io = gdb.debug(binary_name, """
		c
	""", aslr=False)
else:
	io = process(binary_name)

# <interactions>


io.interactive()
