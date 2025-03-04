from spwn.args import Args
from spwn.config import Config
from spwn.file_manage import recognize_binaries, create_debug_dir
from spwn.exe import Exe
from spwn.libc import Libc
from spwn.loader import Loader
from pwn import log

def main():

	# Parse args and config
	args = Args()
	config = Config(args)

	# Recognize binaries
	exe, libc, loader = recognize_binaries(".")
	if exe: log.info(f"Exe: {exe.path}")
	if libc: log.info(f"Libc: {libc.path}")
	if loader: log.info(f"Loader: {loader.path}")
	print()

	if exe:
		# Analyze exe
		exe.print_checksec()
		exe.dangerous_functions(["system", "execve", "gets", "ptrace", "memfrob", "strfry"])
		exe.seccomp()
		# exe.yara()
		exe.cwe()
		print()

	if libc:
		libc.print_version()

		# Download requestes libs (loader included)
		libs_path = libc.download_libs()

		# Create debug dir and populate it from libs path or cwd
		config.debug_dir = create_debug_dir(config.debug_dir, libs_path, exe, libc, loader)

		# Recover downloaded loader
		if libs_path and not loader and exe:
			_, _, loader = recognize_binaries(config.debug_dir, False, False, True)

		# Download libc source
		libc.download_source(config.debug_dir)

		# Patch exe
		if exe and loader:
			exe.patch(loader, config.debug_dir, "{basename}_patched")

	# Interactions
	

	# Create script


