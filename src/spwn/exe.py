from pathlib import Path
import shutil
from pwn import libcdb
from pwnlib.term.text import red, yellow, green
from spwn.utils import log, log_silent, run_command
from spwn.file_manage import recognize_libs, fix_if_exist
from spwn.binary import Binary
from spwn.libc import Libc


class Exe(Binary):
	def __init__(self, filepath: Path) -> None:
		super().__init__(filepath)
		self.path.chmod(0o755)
		self.runnable_path: Path | None = None
		self.set_runnable_path(self.path)

		# Retrieve required libs
		libs_paths: set[str] = set()
		if not self.statically_linked:
			try:
				libs_paths = {lib for lib in self.libs if lib != self.path}
			except:
				ldd_output = run_command(["ldd", self.path], timeout=1)
				if ldd_output:
					libs_paths = {line.strip().split(" ", 1)[0] for line in ldd_output.split("\n") if line and ("linux-vdso" not in line)}
			if not libs_paths:
				log.failure("Impossible to retrieve the requested libs")
		self.required_libs: set[str] = {Path(lib).name for lib in libs_paths}


	def set_runnable_path(self, path: Path) -> None:
		"""Set the exe path that correctly run"""

		# Return if the runnable path is been already found
		if self.runnable_path: return
		
		# Check if path is runnable without errors
		with log_silent:
			check_error = run_command([path], timeout=0.5)
		if check_error is None: return
		
		# Set runnable path
		self.runnable_path = path


	def describe(self):
		log.info("\n".join([
			f"Arch:       {self.arch}-{self.bits}-{self.endian}",
			f"Linking:    {red('Static') if self.statically_linked else green("Dynamic")}",
			f"{self.checksec()}",
		]))


	def check_functions(self, check_functions: list[str]) -> None:
		"""Print some interesting functions used in the executable"""

		found_functions = [red(f) for f in check_functions if f in self.sym]
		if found_functions:
			log.success(f"Interesting functions: {', '.join(found_functions)}")


	def patch(self, patch_path: Path, libc: Libc | None) -> None:
		"""Patch the executable with the given libc"""

		# Return if statically linked or already patched
		if self.statically_linked or self.runpath: return

		# Handle placeholders
		from spwn.placeholders import replace_placeholders
		patch_path = Path(replace_placeholders(f"{patch_path}", self, libc))

		# Create debug dir
		debug_dir = fix_if_exist(patch_path.parent)
		debug_dir.mkdir(parents=True)
		patch_path = debug_dir / patch_path.name

		with log.progress("Patch", "Copying and unstripping libs...") as progress:

			# Get libs names of the required libs
			required_libs_dict = recognize_libs({Path(lib) for lib in self.required_libs})
			loader_path = None

			# Copy the libs from cwd
			for lib, file in recognize_libs(Path(".").iterdir(), required_libs_dict.keys()).items():
				new_path = debug_dir / required_libs_dict[lib]
				shutil.copy2(file, new_path)
				required_libs_dict.pop(lib)

				# Handle specific lib
				if lib == "libc" and libc:
					with log_silent:
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
			progress.status("Run patchelf...")
			cmd_args = ["patchelf", "--set-rpath", debug_dir]
			if loader_path:
				loader_path.chmod(0o755)
				cmd_args += ["--set-interpreter", loader_path]
			cmd_args += ["--output", patch_path, self.path]
			cmd_output = run_command(cmd_args, progress_log=progress)

			# Change exe debug path
			if cmd_output is not None:
				self.debug_path = patch_path.resolve()
				self.set_runnable_path(self.debug_path)

				# Warning about the relative runpath and the relative interpreter path
				if debug_dir.is_relative_to("."):
					if loader_path:
						log.info("The patched exe can run only from this working directory")
					else:
						log.info("The patched exe can run with the fixed libs only from this working directory")


	def seccomp(self, timeout: float = 1) -> None:
		"""Print the seccomp rules if present"""

		# Check if exists a seccomp function
		if ("prctl" in self.sym) or any(True for function in self.sym if function.startswith("seccomp")):
			with log.progress("Seccomp", "Potential seccomp detected, analyzing...") as progress:

				# Use seccompt-tools with the runnable exe
				if self.runnable_path:
					cmd_output = run_command(["seccomp-tools", "dump", f"\'{self.runnable_path}\' </dev/null >&0 2>&0"], progress_log=progress, timeout=timeout)
					if cmd_output:
						progress.success("Found something")
						log.info(cmd_output)
					else:
						progress.success("Not found anything")
				else:
					progress.failure("The executable cannot run")


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
			matches_str = []
			for match in matches:
				addresses = [instance.offset for string_match in match.strings for instance in string_match.instances]
				matches_str.append(f'{match.rule} at {", ".join(map(hex, addresses))}')
			log.info("\n".join(matches_str))


	def cwe(self) -> None:
		"""Print the possible CWEs"""

		with log.progress("CWE", "Analizing... (Press Ctrl-C to interrupt)") as progress:
			cmd_output = run_command(["cwe_checker", self.path], progress_log=progress)
			if cmd_output:
				log.info(cmd_output)
