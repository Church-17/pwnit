class Args:
	def __init__(self) -> None:
		args = self.parse_args()
		self.remote = args["remote"]

	def parse_args(self) -> dict[str, str | None]:
		"""Parse the arguments given to the command into a dict"""

		import argparse
		parser = argparse.ArgumentParser(
			prog="spwn",
			description="spwn is a tool to quickly start a pwn challenge",
		)
		parser.add_argument(
			"-r", "--remote",
			help="Specify the host",
		)
		return parser.parse_args().__dict__
