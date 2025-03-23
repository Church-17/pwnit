from pathlib import Path
from spwn.placeholders import *
from spwn.utils import log, run_command
from spwn.exe import Exe
from spwn.libc import Libc

def run_custom_commands(commands: list[str], exe: Exe | None, libc: Libc | None):

	for cmd in commands:
		new_cmd = (cmd
			.replace(EXE_BASENAME, (exe.path.name if exe else "EXE_BASENAME"))
			.replace(EXE_RELPATH, (str(exe.path.relative_to(Path.cwd(), walk_up=True)) if exe else "EXE_RELPATH"))
			.replace(EXE_ABSPATH, (str(exe.path.resolve()) if exe else "EXE_ABSPATH"))
			.replace(EXE_DEBUG_BASENAME, (exe.debug_path.name if exe else "EXE_DEBUG_BASENAME"))
			.replace(EXE_DEBUG_RELPATH, (str(exe.debug_path.relative_to(Path.cwd(), walk_up=True)) if exe else "EXE_DEBUG_RELPATH"))
			.replace(EXE_DEBUG_ABSPATH, (str(exe.debug_path.resolve()) if exe else "EXE_DEBUG_ABSPATH"))
			.replace(LIBC_BASENAME, (libc.path.name if libc else "LIBC_BASENAME"))
			.replace(LIBC_RELPATH, (str(libc.path.relative_to(Path.cwd(), walk_up=True)) if libc else "LIBC_RELPATH"))
			.replace(LIBC_ABSPATH, (str(libc.path.resolve()) if libc else "LIBC_ABSPATH"))
			.replace(LIBC_DEBUG_BASENAME, (libc.debug_path.name if libc else "LIBC_DEBUG_BASENAME"))
			.replace(LIBC_DEBUG_RELPATH, (str(libc.debug_path.relative_to(Path.cwd(), walk_up=True)) if libc else "LIBC_DEBUG_RELPATH"))
			.replace(LIBC_DEBUG_ABSPATH, (str(libc.debug_path.resolve()) if libc else "LIBC_DEBUG_ABSPATH"))
			.replace(LIBC_ID, (libc.libc_id if libc and libc.libc_id else "LIBC_ID"))
			.replace(LIBC_VERSION, (libc.libc_version if libc and libc.libc_version else "LIBC_VERSION"))
		)

		output = run_command(new_cmd, shell=True)
		if output is not None:
			log.success(f"\"{new_cmd}\" executed")
			if output:
				log.info(output)
