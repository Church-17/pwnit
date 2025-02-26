import argparse

def main():
	parser = argparse.ArgumentParser(
		prog="spwn",
		description="spwn is a tool to quickly start a pwn challenge, for more informations check https://github.com/MarcoMeinardi/spwn"
	)

	parser.add_argument(
		"-i", "--inter",
		action="store_true",
		default=False,
		help="Interactively create interaction functions"
	)

	parser.add_argument(
		"-so", "--sonly",
		action="store_true",
		default=False,
		help="Create the interaction script without analyzing the binary"
	)

	parser.add_argument(
		"-io", "--ionly",
		action="store_true",
		default=False,
		help="Create the interaction functions, without doing any analysis"
	)

	parser.add_argument(
		"-nd", "--nodecomp",
		action="store_true",
		default=False,
		help="Don't open the decompiler"
	)

	parser.add_argument(
		"--config",
		action="store_true",
		default=False,
		help="Setup configs and quit"
	)

	parser.add_argument(
		"others",
		nargs=argparse.REMAINDER,
		help="You can avoid typing the hyphens and/or specify the template"
	)
