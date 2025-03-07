from spwn.binary import Binary
from spwn.loader import Loader
from spwn.utils import run_command
from pwn import log
from pwnlib.term.text import red
import yara
import os
import re


class Exe(Binary):
	def __init__(self, filepath: str) -> None:
		super().__init__(filepath)

		# Retrieve required libs
		self.required_libs = set()
		try:
			self.required_libs = {os.path.basename(lib) for lib in self.libs}
			self.required_libs.remove(os.path.basename(self.path))
		except:
			ldd_output = run_command(["ldd", self.path], timeout=1)
			if ldd_output:
				self.required_libs = {os.path.basename(line.strip().split(" ", 1)[0]) for line in ldd_output.split("\n") if line and ("linux-vdso" not in line)}


	@classmethod
	def check_filetype(cls, filepath: str) -> bool:
		"""Check if a file is an executable"""

		filecmd_output = run_command(["file", "-bL", filepath], timeout=1)
		if filecmd_output:
			match = re.search(r"^ELF [^\,]+ executable", filecmd_output)
			if match:
				return True
		return False


	def print_checksec(self) -> None:
		"""Print the checksec info"""

		self._describe()


	def check_functions(self, check_functions: list[str]) -> None:
		"""Print some darngerous functions used in the executable"""

		found_functions = [red(f) for f in check_functions if f in self.sym]
		if found_functions:
			log.success(f"There are some dangerous functions: {', '.join(found_functions)}")


	def seccomp(self, timeout: float = 1) -> None:
		"""Print the seccomp rules if present"""

		# Check if exists a seccomp function
		if ("prctl" in self.sym) or any(True for function in self.sym if function.startswith("seccomp")):

			# Run command
			cmd_output = run_command(["seccomp-tools", "dump", f"\'{self.debug_path}\' </dev/null >&0 2>&0"], progress=True, timeout=timeout)
			if cmd_output:
				log.info(cmd_output)


	def cwe(self, timeout: float = 10) -> None:
		"""Print the possible cwe"""

		cmd_output = run_command(["cwe_checker", self.path], progress=True, timeout=timeout)
		if cmd_output:
			log.info(cmd_output)


	def yara(self, yara_rules: str) -> None:
		rules = yara.compile(yara_rules)
		matches = rules.match(self.path)
		if matches:
			log.success("Yara found something:")
			for match in matches:
				addresses = [instance.offset for string_match in match.strings for instance in string_match.instances]
				log.info(f'{match.rule} at {", ".join(map(hex, addresses))}')


	def patch(self, loader: Loader, debug_dir: str, output_basename: str) -> None:
		"""Patch the executable with the given loader and runpath, produce a file with the given name in the runpath directory"""

		# Enable some formatting in the name
		output_basename = output_basename.replace("<exe_basename>", os.path.basename(self.path))

		# Run patchelf
		new_debug_path = os.path.join(debug_dir, output_basename)
		cmd_output = run_command([
			"patchelf",
			"--set-interpreter", os.path.join(".", os.path.relpath(loader.debug_path)),
			"--set-rpath", os.path.join(".", os.path.relpath(debug_dir)),
			"--output", new_debug_path,
			self.path,
		], progress=True)

		# Change exe debug path
		if cmd_output is not None:
			self.debug_path = os.path.abspath(new_debug_path)
