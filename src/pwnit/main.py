from pathlib import Path
from pwnit.args import Args
from pwnit.config import Config
from pwnit.file_manage import recognize_exe, recognize_libs
from pwnit.exe import Exe
from pwnit.libc import Libc
from pwnit.interactions import Interactions
from pwnit.template import create_script
from pwnit.commands import run_custom_commands
from pwnit.utils import log

def main():

	# Parse args and config
	args = Args()
	config = Config(args)


	# Recognize exe
	exe_path = recognize_exe(Path(".").iterdir())
	if exe_path:
		exe = Exe(exe_path)
	else:
		exe = None
		log.warning("Exe: not found")

	# Recognize libc
	if (not exe) or ("libc" in exe.required_libs):
		libcs = recognize_libs(Path(exe.runpath.decode() if (exe and exe.runpath) else ".").iterdir(), ["libc"])
		libc = Libc(libcs["libc"]) if ("libc" in libcs) else None
	else:
		libc = None

	print()


	# Do with exe
	if exe:

		# Describe
		exe.describe()
		exe.check_functions(config.check_functions)

		# Patch
		if config.patch_path: exe.patch(config.patch_path, libc)

		# Analyze
		if config.seccomp: exe.seccomp()
		if config.yara_rules: exe.yara(config.yara_rules)
	
		print()


	# Do with libc
	if libc:

		# Download libc source
		if config.libc_source: libc.download_source()

		print()


	# Do with template
	if config.template_path:

		# Interactions
		interactions = Interactions(exe, config.pwntube_variable, config.tab) if config.interactions and exe else None

		# Create script
		create_script(config.template_path, config.script_path, args.remote, exe, libc, interactions)

		print()


	# Run custom commands
	run_custom_commands(config.commands, exe, libc, args.remote)
