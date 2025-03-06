import subprocess
from pwn import log, logging

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


def ask(prompt: str, can_skip: bool = True) -> str:
	print(f" [?] {prompt} > ", end="")
	while True:
		received = input()
		if received or can_skip: return received
