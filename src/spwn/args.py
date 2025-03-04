class Args:
	def __init__(self) -> None:
		args = self.parse_args()
		self.exe = args["exe"]
		self.libc = args["libc"]
		self.loader = args["loader"]
		self.remote = args["remote"]

	def parse_args(self) -> dict[str, str | None]:
		"""Parse the arguments given to the command into a dict"""

		import argparse
		parser = argparse.ArgumentParser(
			prog="spwn",
			description="spwn is a tool to quickly start a pwn challenge",
		)
		parser.add_argument(
			"-e", "--exe",
			help="Specify the executable file",
		)
		parser.add_argument(
			"-l", "--libc",
			help="Specify the libc",
		)
		parser.add_argument(
			"-ld", "--loader",
			help="Specify the loader",
		)
		parser.add_argument(
			"-r", "--remote",
			help="Specify the host",
		)
		return parser.parse_args().__dict__
