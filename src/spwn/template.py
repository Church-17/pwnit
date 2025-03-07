from pwn import log
import re
import os
from spwn.exe import Exe
from spwn.libc import Libc
from spwn.interactions import Interactions

EXE_BASENAME = "<exe_basename>"
EXE_RELPATH = "<exe_relpath>"
EXE_ABSPATH = "<exe_abspath>"
EXE_DEBUG_BASENAME = "<exe_debug_basename>"
EXE_DEBUG_RELPATH = "<exe_debug_relpath>"
EXE_DEBUG_ABSPATH = "<exe_debug_abspath>"
LIBC_BASENAME = "<libc_basename>"
LIBC_RELPATH = "<libc_relpath>"
LIBC_ABSPATH = "<libc_abspath>"
LIBC_DEBUG_BASENAME = "<libc_debug_basename>"
LIBC_DEBUG_RELPATH = "<libc_debug_relpath>"
LIBC_DEBUG_ABSPATH = "<libc_debug_abspath>"
REMOTE = "<remote>"
HOST = "<host>"
PORT = "<port>"
DEBUG_DIR = "<debug_dir>"
INTERACTIONS = "<interactions>"


class Template:
	def __init__(self, path: str) -> None:
		self.template_content: str | None = None
		self.tab_interactions_placeholder: str = ''

		# Check template file
		if not os.path.isfile(path):
			log.failure("Template file doesn't exists. A new script will not be created")
			return

		# Read template file
		with open(path, "r") as template_file:
			self.template_content = template_file.read()

		# Search of tabs before interactions
		match = re.search(rf"([ \t]*){INTERACTIONS}", self.template_content)
		if match:
			self.tab_interactions_placeholder = match.group(1)

	def create_script(self,
			script: str,
			debug_dir: str,
			remote: str | None = None,
			exe: Exe | None = None,
			libc: Libc | None = None,
			interactions: Interactions | None = None,
		) -> None:

		if not self.template_content:
			return None

		new_content = self.template_content
		new_content = new_content.replace(DEBUG_DIR, debug_dir)
		if remote:
			new_content = new_content.replace(REMOTE, remote)
			if ":" in remote:
				host, port = remote.split(":", 1)
				new_content = new_content.replace(HOST, host)
				new_content = new_content.replace(PORT, port)
			else:
				new_content = new_content.replace(HOST, remote)

		if exe:
			new_content = new_content.replace(EXE_BASENAME, os.path.basename(exe.path))
			new_content = new_content.replace(EXE_RELPATH, os.path.join(".", os.path.relpath(exe.path)))
			new_content = new_content.replace(EXE_ABSPATH, os.path.abspath(exe.path))
			new_content = new_content.replace(EXE_DEBUG_BASENAME, os.path.basename(exe.debug_path))
			new_content = new_content.replace(EXE_DEBUG_RELPATH, os.path.join(".", os.path.relpath(exe.debug_path)))
			new_content = new_content.replace(EXE_DEBUG_ABSPATH, os.path.abspath(exe.debug_path))
		if libc:
			new_content = new_content.replace(LIBC_BASENAME, os.path.basename(libc.path))
			new_content = new_content.replace(LIBC_RELPATH, os.path.join(".", os.path.relpath(libc.path)))
			new_content = new_content.replace(LIBC_ABSPATH, os.path.abspath(libc.path))
			new_content = new_content.replace(LIBC_DEBUG_BASENAME, os.path.basename(libc.debug_path))
			new_content = new_content.replace(LIBC_DEBUG_RELPATH, os.path.join(".", os.path.relpath(libc.debug_path)))
			new_content = new_content.replace(LIBC_DEBUG_ABSPATH, os.path.abspath(libc.debug_path))
		if interactions:
			new_content = new_content.replace(INTERACTIONS, interactions.dump(self.tab_interactions_placeholder))

		with open(script, "w") as script_file:
			script_file.write(new_content)

		log.success("Script \'{script}\' created")
