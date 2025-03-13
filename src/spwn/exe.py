import os
from pathlib import Path
import shutil
from pwn import log, libcdb, context
from pwnlib.term.text import red, yellow, green
from spwn.utils import run_command, fix_if_exist
from spwn.file_manage import recognize_libs
from spwn.binary import Binary
from spwn.libc import Libc


class Exe(Binary):
	def __init__(self, filepath: Path) -> None:
		super().__init__(filepath)

		# Retrieve required libs
		self.required_libs: set[str] = set()
		if not self.statically_linked:
			try:
				self.required_libs = {Path(Path(lib).name) for lib in self.libs if lib != self.path}
			except:
				ldd_output = run_command(["ldd", self.path], timeout=1)
				if ldd_output:
					self.required_libs = {Path(Path(line.strip().split(" ", 1)[0]).name) for line in ldd_output.split("\n") if line and ("linux-vdso" not in line)}
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


	def patch(self, patch_path: Path, cwd_libs: dict[str, Path], libc: Libc | None) -> None:
		"""Patch the executable with the given libc"""

		# Handle 
		patch_path = Path(str(patch_path).replace("<exe_basename>", self.path.name))

		# Create debug dir
		debug_dir = fix_if_exist(patch_path.parent)
		debug_dir.mkdir(parents=True)
		patch_path = debug_dir / patch_path.name

		with log.progress("Patch", "Copying and unstripping libs...") as waiting:

			# Get libs names of the required libs
			required_libs_dict = recognize_libs(self.required_libs)
			loader_path = None

			# Copy the libs from cwd
			for lib, file in cwd_libs.items():
				if lib in required_libs_dict:
					new_path = debug_dir / required_libs_dict[lib]
					shutil.copy2(file, new_path)
					required_libs_dict.pop(lib)

					# Handle specific lib
					if lib == "libc" and libc:
						with context.silent:
							try:
								libcdb.unstrip_libc(str(new_path))
							except:
								pass
						libc.debug_path = new_path.resolve()
					elif lib == "ld":
						loader_path = new_path

			# Copy libs from downloaded libs
			if libc and libc.libs_path:
				libs_set = {Path(lib.name) for lib in libc.libs_path.iterdir()}
				for lib, file in required_libs_dict.copy().items():
					if file in libs_set:
						shutil.copy2(libc.libs_path / file, debug_dir)
						required_libs_dict.pop(lib)

						# Handle specific lib
						if lib == "ld":
							loader_path = debug_dir / file
				
			# Check missing libs
			if required_libs_dict:
				log.warning(f"Missing libs for patch: {', '.join([yellow(str(lib)) for lib in required_libs_dict.values()])}")

			# Run patchelf
			waiting.status("Run patchelf...")
			cmd_args = ["patchelf", "--set-rpath", debug_dir]
			if loader_path:
				loader_path.chmod(0o755)
				cmd_args += ["--set-interpreter", loader_path]
			cmd_args += ["--output", patch_path, self.path]
			cmd_output = run_command(cmd_args, progress=waiting)

			# Change exe debug path
			if cmd_output is not None:
				self.debug_path = patch_path.resolve()


	def seccomp(self, timeout: float = 1) -> None:
		"""Print the seccomp rules if present"""

		# Check if exists a seccomp function
		if ("prctl" in self.sym) or any(True for function in self.sym if function.startswith("seccomp")):
			with log.progress("Seccomp", "Potential seccomp detected, analyzing...") as waiting:
				
				# Check if exe can run
				for path in [self.debug_path, self.path]:
					with context.silent:
						check_error = run_command([path], timeout=0.5)

					# Run command if exe doesn't return an error
					if check_error is not None:
						cmd_output = run_command(["seccomp-tools", "dump", f"\'{self.debug_path}\' </dev/null >&0 2>&0"], progress=waiting, timeout=timeout)
						if cmd_output:
							waiting.success("Found something")
							log.info(cmd_output)
						else:
							waiting.success("Not found anything")
						break
				else:
					waiting.failure("Executable returns an error")


	def yara(self, yara_rules: Path) -> None:
		"""Search for pattern with yara"""

		# Check Yara rules file
		if not yara_rules.is_file():
			log.failure("Yara rules file doesn't exists. The exe will not be analyzed with yara")
			return

		# Search patterns
		import yara
		rules = yara.compile(str(yara_rules))
		matches = rules.match(str(self.path))
		if matches:
			log.success("Yara found something:")
			for match in matches:
				addresses = [instance.offset for string_match in match.strings for instance in string_match.instances]
				log.info(f'{match.rule} at {", ".join(map(hex, addresses))}')


	def cwe(self) -> None:
		"""Print the possible CWEs"""

		with log.progress("CWE", "Analizing... (Press Ctrl-C to interrupt)") as waiting:
			cmd_output = run_command(["cwe_checker", self.path], progress=waiting)
			if cmd_output:
				log.info(cmd_output)
