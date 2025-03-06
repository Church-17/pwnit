from spwn.args import Args
from spwn.config import Config
from spwn.file_manage import recognize_binaries, create_debug_dir

def main():

	# Parse args and config
	args = Args()
	config = Config(args)

	# Recognize binaries
	exe, libc, loader = recognize_binaries(".")
	print()

	if libc:
		libc.print_version()

		# Download requestes libs (loader included)
		libs_path = libc.download_libs()

		# Create debug dir and populate it from libs path or cwd
		debug_dir = create_debug_dir(config.debug_dir, libs_path, exe, libc, loader)

		# Download libc source
		if config.download_libc_source: libc.download_source(debug_dir)

		if exe:
			# Recover downloaded loader (will be found in the debug dir if it is requested by the exe)
			if libs_path and (not loader):
				_, _, loader = recognize_binaries(debug_dir, False, False, True)

			# Patch exe
			if config.patch and loader: exe.patch(loader, debug_dir, config.patch)

		# Set libc and loader executable
		libc.set_executable()
		if loader: loader.set_executable()
		print()
	
	# Fix absent debug dir
	else:
		debug_dir = "."

	if exe:
		# Set exe executable
		exe.set_executable()

		# Analyze exe
		exe.print_checksec()
		exe.check_functions(config.check_functions)
		exe.seccomp()
		if config.yara_rules: exe.yara(config.yara_rules)
		if config.cwe: exe.cwe()
		print()

	# Interactions
	

	# Create script


