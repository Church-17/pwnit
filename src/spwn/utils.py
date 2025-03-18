import subprocess
from pwn import log, options
from pwnlib.log import Progress, Logger


def ask(prompt: str, can_skip: bool = True) -> str:
	while True:
		received = input(f" [?] {prompt} > ")
		if received or can_skip: return received
		log.warning("Can't skip")


def choose(prompt: str, opts: list, default: int | None = None) -> int:
	assert opts
	if len(opts) == 1: return 0
	return options(prompt, list(map(str, opts)), default)


def run_command(args: list, progress: Progress | Logger = log, **kwargs) -> str | None:
	"""Run a command, logging out failures msg in the progress or in the log"""
	
	assert len(args) >= 1

	# Try executing command
	try:
		cmd_output = subprocess.check_output(args, stderr=subprocess.DEVNULL, encoding="latin-1", **kwargs)
		return cmd_output

	# Handle command not found
	except FileNotFoundError as err:
		progress.failure(f"To execute this please install {args[0]}")

	# Handle interrupt
	except KeyboardInterrupt as err:
		progress.failure(f"{args[0]} interrupted")

	# Handle errors
	except subprocess.CalledProcessError as err:
		progress.failure(f"{args[0]} failed")
		log.debug(err)
		log.debug(err.stderr)

	# Handle timeout
	except subprocess.TimeoutExpired as err:
		log.debug(f"{args[0]} timeout")
		return ""

	return None
