import logging
import os
import subprocess
import shutil
from pwn import log, options


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


def run_command(args: list[str], progress: bool = False, **kwargs) -> str | None:
	assert len(args) >= 1

	# Print progress if requested
	level = logging.INFO if progress else logging.DEBUG
	with log.progress(args[0], "Analyzing... (press Ctrl+C to stop)", level=level) as waiting:

		# Try executing command
		try:
			cmd_output = subprocess.check_output(args, encoding="latin-1", **kwargs)
			waiting.success("Success!")
			return cmd_output

		# Handle command not found
		except FileNotFoundError as err:
			waiting.failure(f"To analyze please install {args[0]}")

		# Handle interrupt
		except KeyboardInterrupt as err:
			waiting.failure(f"Interrupted")

		# Handle errors
		except subprocess.CalledProcessError as err:
			waiting.failure("Failed!")
			log.debug(err)

		# Handle timeout
		except subprocess.TimeoutExpired as err:
			waiting.success("Unsuccessful")
			log.debug("Timeout")

	return None
