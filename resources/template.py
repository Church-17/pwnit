from pwn import *

binary_name = "<exe_relpath>"
exe  = ELF(binary_name, checksec=True)
libc = ELF("<libc_relpath>", checksec=False)
context.binary = exe

ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)

if args.REMOTE:
	io = connect("<host>", "<port>")
elif args.GDB:
	io = gdb.debug("<exe_debug_relpath>", """
		c
	""", aslr=False)
else:
	io = process(f"<exe_debug_relpath>")

<interactions>


io.interactive()
