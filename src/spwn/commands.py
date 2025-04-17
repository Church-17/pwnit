from pwnlib.term.text import blue
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
		new_cmd = replace_placeholders(cmd, exe, libc, remote, keep_missing=False)
		if not new_cmd: continue

		# Run command
		with log.progress(f"Command: {blue(new_cmd)} ") as progress:
			output = run_command(new_cmd, progress, shell=True)
			if output is not None:
				progress.success()
				if output:
					log.info(output)
