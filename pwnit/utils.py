from typing import TypeVar
import subprocess
import socket
from pwn import log, context, options
from pwnlib.log import Progress, Logger
from pwnlib.term.text import yellow

log_silent = context.silent


def ask(prompt: str, can_skip: bool = True) -> str:
	while True:
		received = input(f" [{yellow('?')}] {prompt} > ")
		if received or can_skip: return received
		log.warning("Can't skip")


ElementT = TypeVar("ElementT")
def choose(opts: list[ElementT], prompt: str = "Choose:", default: int | None = None) -> ElementT:
	assert opts
	if len(opts) == 1: return opts[0]
	return opts[options(f"\r [{yellow('?')}] {prompt}", list(map(str, opts)), default)]


def run_command(
		args: list | str,
		progress_log: Progress | Logger | None = log,
		**kwargs,
	) -> str | None:
	"""
	Run a command, logging out failures messages in the progress or in the log.
	This function returns the output of the command, `None` on error, and `""` on timeout.
	"""
	
	assert args
	cmd = args.split(" ")[0] if isinstance(args, str) else args[0]

	# Try executing command
	try:
		return subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True, **kwargs)

	# Handle command not found
	except FileNotFoundError as err:
		if progress_log:
			progress_log.failure(f"To execute this please install {cmd}")

	# Handle interrupt
	except KeyboardInterrupt as err:
		if progress_log:
			progress_log.failure(f"{cmd} interrupted")

	# Handle errors
	except subprocess.CalledProcessError as err:
		if progress_log:
			progress_log.failure(f"{cmd} failed")
		log.debug(err)
		log.debug(err.stderr)

	# Handle timeout
	except subprocess.TimeoutExpired as err:
		log.debug(f"{cmd} timeout")
		return ""

	return None


def check_internet():
	try:
		socket.create_connection(("8.8.8.8", 53), timeout=3)
		return True
	except:
		log.warning("Missing internet")
		return False

connection = check_internet()
