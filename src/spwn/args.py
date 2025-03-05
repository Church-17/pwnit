import argparse

class Args:
	def __init__(self) -> None:

		args = self.parse_args()

		self.remote: str | None		= args["remote"]
		self.interactions: bool		= args["interactions"]
		self.template: str | None	= args["template"]
		self.only: bool				= args["only"]
		self.yara: str | None		= args["yara"]
		self.cwe: bool				= args["cwe"]
		self.patch: str | None		= args["patch"]
		self.source: str | None		= args["source"]

	def parse_args(self) -> dict[str]:
		"""Parse the arguments given to the command into a dict"""

		parser = argparse.ArgumentParser(
			prog="spwn",
			description="spwn is a tool to quickly start a pwn challenge",
		)
		parser.add_argument(
			"-r", "--remote",
			help="Specify the host:port",
		)
		parser.add_argument(
			"-i", "--interactions",
			help="Create the interactions",
			action="store_true",
		)
		parser.add_argument(
			"-t", "--template",
			help="Create the script from a template",
		)
		parser.add_argument(
			"-o", "--only",
			help="Do only the actions specified via args",
			action="store_true",
		)
		parser.add_argument(
			"--yara",
			help="Specify the yara rules",
		)
		parser.add_argument(
			"--cwe",
			help="Check for CWEs",
			action="store_true",
		)
		parser.add_argument(
			"--patch",
			help="Patch the exe with a specific name",
		)
		parser.add_argument(
			"--source",
			help="Donwload the libc source",
			action="store_true",
		)
		return parser.parse_args().__dict__
