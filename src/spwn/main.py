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

	if exe:
		# Analyze exe
		exe.print_checksec()
		exe.check_functions(config.check_functions)
		exe.seccomp()
		if config.yara_rules: exe.yara(config.yara_rules)
		if config.cwe: exe.cwe()
		print()

	if libc:
		libc.print_version()

		# Download requestes libs (loader included)
		libs_path = libc.download_libs()

		# Create debug dir and populate it from libs path or cwd
		debug_dir = create_debug_dir(config.debug_dir, libs_path, exe, libc, loader)

		# Recover downloaded loader
		if libs_path and (not loader) and exe:
			_, _, loader = recognize_binaries(debug_dir, False, False, True)

		# Patch exe
		if config.patch and exe and loader: exe.patch(loader, debug_dir, config.patch)

		# Download libc source
		if config.download_libc_source: libc.download_source(debug_dir)
	
	# Fix absent debug dir
	else:
		debug_dir = "."

	# Interactions
	

	# Create script


