class Args:
	def __init__(self) -> None:

		args = self.parse_args()

		self.remote: str		= args["remote"]
		# self.only: bool			= args["only"]
		self.interactions: bool	= args["interactions"]
		self.template: str		= args["template"]

	def parse_args(self) -> dict[str]:
		"""Parse the arguments given to the command into a dict"""

		import argparse
		parser = argparse.ArgumentParser(
			prog="spwn",
			description="spwn is a tool to quickly start a pwn challenge",
		)
		# parser.add_argument(
		# 	"-o", "--only",
		# 	help="Do only the actions specified by the args",
		# 	action="store_true",
		# )
		parser.add_argument(
			"-i", "--interactions",
			help="Do the interactions",
			action="store_true",
		)
		parser.add_argument(
			"-r", "--remote",
			help="Specify the host:port",
		)
		parser.add_argument(
			"-t", "--template",
			help="Specify the template",
		)
		return parser.parse_args().__dict__
