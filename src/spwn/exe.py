import os
import shutil
from pwn import log, libcdb, context
from pwnlib.term.text import red, yellow, green
from spwn.utils import run_command, fix_if_exist
from spwn.file_manage import recognize_libs
from spwn.binary import Binary
from spwn.libc import Libc


class Exe(Binary):
	def __init__(self, filepath: str) -> None:
		super().__init__(filepath)

		# Retrieve required libs
		self.required_libs = set()
		if not self.statically_linked:
			try:
				self.required_libs = {os.path.basename(lib) for lib in self.libs if lib != self.path}
			except:
				ldd_output = run_command(["ldd", self.path], timeout=1)
				if ldd_output:
					self.required_libs = {os.path.basename(line.strip().split(" ", 1)[0]) for line in ldd_output.split("\n") if line and ("linux-vdso" not in line)}
			if not self.required_libs:
				log.failure("Impossible to retrieve the requested libs")


	def describe(self):
		log.info("\n".join([
			f"Arch:       {self.arch}-{self.bits}-{self.endian}",
			f"Linking:    {red('Static') if self.statically_linked else green("Dynamic")}",
			f"{self.checksec()}",
		]))


	def check_functions(self, check_functions: list[str]) -> None:
		"""Print some darngerous functions used in the executable"""

		found_functions = [red(f) for f in check_functions if f in self.sym]
		if found_functions:
			log.success(f"There are some dangerous functions: {', '.join(found_functions)}")


	def patch(self, patch_path: str, cwd_libs: dict[str, str], libc: Libc | None) -> None:
		"""Patch the executable with the given libc"""

		# Create debug dir
		patch_path = patch_path.replace("<exe_basename>", os.path.basename(self.path))
		debug_dir = fix_if_exist(os.path.dirname(patch_path))
		os.makedirs(debug_dir)

		# Get libs names of the required libs
		required_libs_dict = recognize_libs(self.required_libs)
		loader_path = None

		# Copy the libs from cwd
		for lib, file in cwd_libs.items():
			if lib in required_libs_dict:
				new_path = os.path.join(debug_dir, required_libs_dict[lib])
				shutil.copy2(file, new_path)
				required_libs_dict.pop(lib)

				# Handle specific lib
				if lib == "libc" and libc:
					with context.silent:
						try:
							libcdb.unstrip_libc(new_path)
						except:
							pass
					libc.debug_path = new_path
				elif lib == "ld":
					loader_path = new_path

		# Copy libs from downloaded libs
		if libc and libc.libs_path:
			libs_set = set(os.listdir(libc.libs_path))
			for lib, file in required_libs_dict.copy().items():
				if file in libs_set:
					shutil.copy2(os.path.join(libc.libs_path, file), debug_dir)
					required_libs_dict.pop(lib)

					# Handle specific lib
					if lib == "ld":
						loader_path = os.path.join(debug_dir, file)
			
		# Check missing libs
		if required_libs_dict:
			log.warning(f"Missing libs for patch: {', '.join([yellow(lib) for lib in required_libs_dict.values()])}")

		# Run patchelf
		new_debug_path = os.path.join(debug_dir, os.path.basename(patch_path))
		cmd_args = ["patchelf", "--set-rpath", os.path.join(".", os.path.relpath(debug_dir))]
		if loader_path:
			os.chmod(loader_path, 0o755)
			cmd_args += ["--set-interpreter", os.path.join(".", os.path.relpath(loader_path))]
		cmd_args += ["--output", new_debug_path, self.path]
		cmd_output = run_command(cmd_args, progress=True)

		# Change exe debug path
		if cmd_output is not None:
			self.debug_path = new_debug_path


	def seccomp(self, timeout: float = 1) -> None:
		"""Print the seccomp rules if present"""

		# Check if exists a seccomp function
		if ("prctl" in self.sym) or any(True for function in self.sym if function.startswith("seccomp")):

			# Run command
			cmd_output = run_command(["seccomp-tools", "dump", f"\'{self.debug_path}\' </dev/null >&0 2>&0"], progress=True, timeout=timeout)
			if cmd_output:
				log.info(cmd_output)


	def yara(self, yara_rules: str) -> None:
		"""Search for pattern with yara"""

		if not os.path.isfile(yara_rules):
			log.failure("Yara rules file doesn't exists. The exe will not be analyzed with yara")
			return

		import yara
		rules = yara.compile(yara_rules)
		matches = rules.match(self.path)
		if matches:
			log.success("Yara found something:")
			for match in matches:
				addresses = [instance.offset for string_match in match.strings for instance in string_match.instances]
				log.info(f'{match.rule} at {", ".join(map(hex, addresses))}')


	def cwe(self, timeout: float = 10) -> None:
		"""Print the possible CWEs"""

		cmd_output = run_command(["cwe_checker", self.path], progress=True, timeout=timeout)
		if cmd_output:
			log.info(cmd_output)
