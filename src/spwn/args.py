class Args:
	def __init__(self) -> None:

		args = self.parse_args()

		self.only: bool			= args["only"]
		self.remote: str		= args["remote"]
		self.interactions: bool	= args["interactions"]
		self.template: str		= args["template"]
		self.source: str		= args["source"]

	def parse_args(self) -> dict[str]:
		"""Parse the arguments given to the command into a dict"""

		import argparse
		parser = argparse.ArgumentParser(
			prog="spwn",
			description="spwn is a tool to quickly start a pwn challenge",
		)
		parser.add_argument(
			"-o", "--only",
			help="Do only the actions specified via args",
			action="store_true",
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
			help="Create the script from the template",
			action="store_true",
		)
		parser.add_argument(
			"-s", "--source",
			help="Donwload the libc source",
			action="store_true",
		)
		return parser.parse_args().__dict__
