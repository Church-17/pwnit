from spwn.utils import log, run_command
from spwn.exe import Exe
from spwn.libc import Libc
from spwn.placeholders import replace_placeholders

def run_custom_commands(
		commands: list[str],
		exe: Exe | None,
		libc: Libc | None,
		remote: str,
	):

	for cmd in commands:

		# Handle placeholders in commands (skip if a placeholder can't be substitute)
		new_cmd = replace_placeholders(cmd, exe, libc, remote, use_defaults=False)
		if not new_cmd: continue

		# Run command
		output = run_command(new_cmd, shell=True)
		if output is not None:
			log.success(f"\"{new_cmd}\" executed")
			if output:
				log.info(output)
