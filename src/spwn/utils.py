import os
from pathlib import Path
import subprocess
import shutil
from pwn import log, options
from pwnlib.log import Progress


def ask(prompt: str, can_skip: bool = True) -> str:
	while True:
		received = input(f" [?] {prompt} > ")
		if received or can_skip: return received
		log.warning("Can't skip")


def choose(prompt: str, opts: list, default: int | None = None) -> int:
	assert opts
	if len(opts) == 1: return 0
	return options(prompt, list(map(str, opts)), default)


def handle_path(path: str | None) -> Path | None:
	return Path(path).expanduser() if path else None


def check_file(path: Path) -> bool:
	if not path.is_file():
		if path.exists():
			raise FileExistsError(f"{path} exists but it's not a regular file")
		return False
	return True


def check_dir(path: Path) -> bool:
	if not path.is_dir():
		if path.exists():
			raise FileExistsError(f"{path} exists but it's not a directory")
		return False
	return True


def fix_if_exist(path: Path) -> Path:
	"""Check if debug dir exists, in case ask for a new name"""

	while path.exists():
		new_name = ask(f"{path} already exists: type another name (empty to overwrite)")
		if new_name:
			if "/" in new_name:
				log.warning("Insert only the basename directory")
			else:
				path = path.parent / new_name
		else:
			if path.is_dir():
				shutil.rmtree(path)
			else:
				path.unlink()
			break
	return path


def run_command(args: list, progress: Progress | None = None, **kwargs) -> str | None:
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
