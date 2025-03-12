import os
import subprocess
import shutil
from pwn import log, options
from pwnlib.log import Progress


def ask(prompt: str, can_skip: bool = True) -> str:
	while True:
		received = input(f" [?] {prompt} > ")
		if received or can_skip: return received
		log.warning("Can't skip")


def choose(prompt: str, opts: list[str], default: int | None = None) -> int:
	assert opts
	if len(opts) == 1: return 0
	return options(prompt, opts, default)


def fix_if_exist(path: str) -> str:
	"""Check if debug dir exists, in case ask for a new name"""

	while os.path.exists(path):
		new_name = ask(f"{path} already exists: type another name (empty to overwrite)")
		if new_name:
			path = new_name
		else:
			if os.path.isdir(path):
				shutil.rmtree(path)
			else:
				os.remove(path)
			break
	return path


def run_command(args: list[str], progress: Progress | None = None, **kwargs) -> str | None:
	"""Run a command, logging out failures msg in the progress or in the log"""
	
	assert len(args) >= 1

	def failure(msg: str):
		if progress:
			progress.failure(msg)
		else:
			log.failure(msg)

	# Try executing command
	try:
		cmd_output = subprocess.check_output(args, encoding="latin-1", **kwargs)
		return cmd_output

	# Handle command not found
	except FileNotFoundError as err:
		failure(f"To execute this please install {args[0]}")

	# Handle interrupt
	except KeyboardInterrupt as err:
		failure(f"{args[0]} interrupted")

	# Handle errors
	except subprocess.CalledProcessError as err:
		failure(f"{args[0]} failed")
		log.debug(err)
		log.debug(err.stderr)

	# Handle timeout
	except subprocess.TimeoutExpired as err:
		log.debug(f"{args[0]} timeout")
		return ""

	return None
