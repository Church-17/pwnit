import re
from pathlib import Path
import shutil
import requests
from spwn.utils import ask, choose, run_command


def recognize_exe(path_list: list[Path]) -> Path | None:
	"""Recognize the executable from a list of files"""

	# Initialize potential executables list
	possible_exes: list[Path] = []

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


def recognize_libs(path_list: list[Path], libs_names: list[str] = []) -> dict[str, Path]:
	"""Recognize the libs from a list of files, filtering for some of them"""

	# Initialize potential libraries lists
	possible_libs: dict[str, list[Path]] = {}
	search_for = r'|'.join(libs_names) if libs_names else r"[A-Za-z]+"

	# Loop through path
	for file in path_list:

		# Search libs regex
		match = re.search(rf"^({search_for})(?:[^A-Za-z].*)?\.so", file.name)
		if not match: continue

		# Append file to possible libs
		lib_name = match.group(1)
		if not lib_name in possible_libs:
			possible_libs[lib_name] = [file]
		else:
			possible_libs[lib_name].append(file)

	# Select actual libs and return them
	return {lib_name: opts[choose(f"Select {lib_name}:", opts)] for lib_name, opts in possible_libs.items()}


def handle_path(path: str | None) -> Path | None:
	return Path(path).expanduser() if path else None


def relative_path(path: Path) -> Path:
	return path.relative_to(Path.cwd()) if path.is_relative_to(Path.cwd()) else path


def check_file(path: Path) -> bool:
	if not path.is_file():
		if path.exists():
			raise FileExistsError(f"{path} exists but it's not a regular file")
		return False
	return True


def check_dir(path: Path) -> bool:
	if not path.is_dir():
		if path.exists():
			raise FileExistsError(f"{path} exists but it's not a directory")
		return False
	return True


def fix_if_exist(path: Path) -> Path:
	"""Check if debug dir exists, in case ask for a new name"""

	while path.exists():
		new_name = ask(f"{path} already exists: type another path (empty to overwrite)")
		if new_name:
			path = Path(new_name)
		else:
			if path.is_dir():
				shutil.rmtree(path)
			else:
				path.unlink()
			break
	return path


def download_file(filepath: Path, url: str) -> None:
	if not check_file(filepath):
		try:
			response = requests.get(url)
			if response:
				filepath.write_text(response.text)
		except:
			pass

