import re
import os
from spwn.utils import choose, run_command


def recognize_exe(path_list: list[str]) -> str | None:
	"""Recognize the executable from a list of files"""

	# Initialize potential executables list
	possible_exes: list[str] = []

	# Loop through path list
	for file in path_list:

		# Execute file command
		filecmd_output = run_command(["file", "-bL", file], timeout=1)
		if not filecmd_output: continue

		# Search executable regex
		match = re.search(r"^ELF [^\,]+ executable", filecmd_output)
		if not match: continue

		possible_exes.append(file)

	# Return correct executable path or none
	return possible_exes[choose("Select executable:", possible_exes)] if possible_exes else None


def recognize_libs(path_list: list[str], libs_names: list[str] = []) -> dict[str, str]:
	"""Recognize the libs from a list of files, filtering for some of them"""

	# Initialize potential libriaries lists
	possible_libs: dict[str, list[str]] = {}

	# Loop through path
	for file in path_list:

		# Search libs regex
		search_for = r'|'.join(libs_names) if libs_names else r"[A-Za-z]+"
		match = re.search(rf"^({search_for})(?:[^A-Za-z].*)?\.so", os.path.basename(file))
		if not match: continue

		# Append file to possible libs
		lib_name = match.group(1)
		if not lib_name in possible_libs:
			possible_libs[lib_name] = [file]
		else:
			possible_libs[lib_name].append(file)

	# Select actual libs and return them
	return {lib_name: opts[choose(f"Select {lib_name}:", opts)] for lib_name, opts in possible_libs.items()}
