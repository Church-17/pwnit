from pathlib import Path
from spwn.args import Args
from spwn.config import Config
from spwn.file_manage import recognize_exe, recognize_libs
from spwn.exe import Exe
from spwn.libc import Libc
from spwn.interactions import Interactions
from spwn.template import create_script
from spwn.commands import run_custom_commands
from spwn.utils import log

def main():

	# Parse args and config
	args = Args()
	config = Config(args)


	# Recognize exe
	exe = None
	exe_path = recognize_exe(Path(".").iterdir())
	if exe_path:
		exe = Exe(exe_path)
	else:
		log.warning("Exe not found")

	# Recognize libc
	libc = None
	if not (exe and exe.statically_linked):
		libcs = recognize_libs(Path(exe.runpath.decode() if (exe and exe.runpath) else ".").iterdir(), ["libc"])
		if "libc" in libcs:
			libc = Libc(libcs["libc"])

	print()


	# Do with exe
	if exe:

		# Describe
		exe.describe()
		exe.check_functions(config.check_functions)

		# Patch
		if config.patch_path and (not exe.statically_linked) and (not exe.runpath): exe.patch(config.patch_path, libc)

		# Analyze
		if config.seccomp: exe.seccomp()
		if config.yara_rules: exe.yara(config.yara_rules)
		if config.cwe: exe.cwe()
	
		print()


	# Do with libc
	if libc:

		# Download libc source
		if config.download_libc_source: libc.download_source()

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
