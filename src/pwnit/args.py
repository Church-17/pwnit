import re

class Args:
	def __init__(self) -> None:

		args = self.parse_args()

		self.remote: str | None		= args["remote"]
		self.interactions: bool		= args["interactions"]
		self.template: str | None	= args["template"]
		self.only: bool				= args["only"]
		self.libc_source: bool		= args["libc_source"]
		self.patch: bool			= args["patch"]
		self.seccomp: bool			= args["seccomp"]
		self.yara: bool				= args["yara"]

		if self.remote and not re.search(r"^[^\:]+\:\d+$", self.remote):
			raise ValueError("Remote parameter without the correct syntax '<host>:<port>'")


	def parse_args(self) -> dict[str]:
		"""Parse the arguments given to the command into a dict"""

		import argparse
		parser = argparse.ArgumentParser(
			prog="pwnit",
			description="pwnit is a tool to quickly start a pwn challenge",
		)
		parser.add_argument(
			"-r", "--remote",
			help="Specify <host>:<port>",
		)
		parser.add_argument(
			"-i", "--interactions", action="store_true",
			help="Create the interactions",
		)
		parser.add_argument(
			"-t", "--template",
			help="Create the script from the template",
		)
		parser.add_argument(
			"-o", "--only", action="store_true",
			help="Do only the actions specified in args",
		)
		parser.add_argument(
			"--libc-source", action="store_true",
			help="Donwload the libc source",
		)
		parser.add_argument(
			"--patch", action="store_true",
			help="Patch the executable with the specified path",
		)
		parser.add_argument(
			"--seccomp", action="store_true",
			help="Print seccomp rules if present",
		)
		parser.add_argument(
			"--yara", action="store_true",
			help="Check for given Yara rules",
		)

		return parser.parse_args().__dict__
