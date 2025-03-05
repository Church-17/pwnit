from spwn.exe import Exe
from spwn.libc import Libc
from spwn.loader import Loader
from spwn.utils import ask, run_command
from pwn import options, log
import os
import shutil


def recognize_binaries(
		dirpath: str,
		search_exe: bool = True,
		search_libc: bool = True,
		search_loader: bool = True,
	) -> tuple[Exe | None, Libc | None, Loader | None]:
	"""Recognize the executable, libc and loader from a directory"""
	
	exe, libc, loader = None, None, None
	all_files = [os.path.join(dirpath, file) for file in os.listdir(dirpath)]

	if search_exe:
		exes = [file for file in all_files if Exe.check_filetype(file)]
		if exes:
			exe = Exe(exes[(options("Select executable:", exes) if len(exes) > 1 else 0)])
			log.info(f"Exe: {exe.path}")
			if exe.statically_linked:
				log.warning("Exe statically linked")
				return (exe, None, None)
		
	if search_libc:
		libcs = [file for file in all_files if Libc.check_filetype(file)]
		if libcs:
			libc = Libc(libcs[(options("Select libc:", libcs) if len(libcs) > 1 else 0)])
			log.info(f"Libc: {libc.path}")
		
	if search_loader:
		loaders = [file for file in all_files if Loader.check_filetype(file)]
		if loaders:
			loader = Loader(loaders[(options("Select loader:", loaders) if len(loaders) > 1 else 0)])
			log.info(f"Loader: {loader.path}")

	return (exe, libc, loader)


def create_debug_dir(
		debug_dir: str,
		libs_path: str | None = None,
		exe: Exe | None = None,
		libc: Libc | None = None,
		loader: Loader | None = None,
	) -> tuple[str]:
	"""Create debug dir, populate it, update debug paths"""

	# Check if debug dir exists, in case ask for a new name
	while os.path.exists(debug_dir):
		new_name = ask(f"{debug_dir} already exists: type another name or leave empty to overwrite")
		if new_name:
			debug_dir = new_name
		else:
			shutil.rmtree(debug_dir)
			break

	# Create debug dir
	os.mkdir(debug_dir)

	# Try to retrieve the requested libs by the exe
	if exe:
		try:
			requested_libs = {os.path.basename(lib) for lib in exe.libs}
			requested_libs.remove(os.path.basename(exe.path))
		except:
			ldd_output = run_command(["ldd", exe.path], timeout=1)
			if ldd_output:
				requested_libs = {os.path.basename(line.strip().split(" ", 1)[0]) for line in ldd_output.split("\n") if line and "linux-vdso" not in line}
			else:
				requested_libs = {}

	if requested_libs:
		# If libs are been downloaded...
		if libs_path:

			# Copy the libs requested by the exe from libs path to debug dir (if not exe, copy all of them)
			libs_to_copy = set(os.listdir(libs_path)) & requested_libs
			for lib in libs_to_copy:
				shutil.copy2(os.path.join(libs_path, lib), debug_dir)
				requested_libs.remove(lib)

				# From the copied libs, identify libc and loader, and update their debug path
				filepath = os.path.join(debug_dir, lib)
				if libc and Libc.check_filetype(filepath):
					libc.debug_path = filepath
				elif loader and Loader.check_filetype(filepath):
					loader.debug_path = filepath

		# Copy the remained requested libs from cwd, with the names requested by the exe
		for lib in requested_libs:
			filepath = os.path.join(debug_dir, lib)
			shutil.copy2(lib, filepath)
			if libc and Libc.check_filetype(lib):
				libc.debug_path = filepath
			elif loader and Loader.check_filetype(lib):
				loader.debug_path = filepath
	
	# If failed to retrieve the requested libs, copy just libc and loader
	else:
		if libc:
			shutil.copy2(libc.path, debug_dir)
			libc.debug_path = os.path.join(debug_dir, os.path.basename(libc.path))
		if loader:
			shutil.copy2(loader.path, debug_dir)
			loader.debug_path = os.path.join(debug_dir, os.path.basename(loader.path))

	# Return the actual debug dir
	return debug_dir
