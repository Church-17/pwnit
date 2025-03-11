import re
import os
from pwn import log
from spwn.utils import fix_if_exist
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
			remote: str | None = None,
			exe: Exe | None = None,
			libc: Libc | None = None,
			interactions: Interactions | None = None,
		) -> None:

		if not self.template_content: return

		# Handle host and port from remote
		host, port = remote.split(":", 1) if remote and ":" in remote else (None, None)

		# Replace placeholders
		replacements = {
			REMOTE: remote or "REMOTE",
			HOST: host or "HOST",
			PORT: port or "PORT",
			EXE_BASENAME: os.path.basename(exe.path) if exe else "EXE_BASENAME",
			EXE_RELPATH: os.path.join(".", os.path.relpath(exe.path)) if exe else "EXE_RELPATH",
			EXE_ABSPATH: os.path.abspath(exe.path) if exe else "EXE_ABSPATH",
			EXE_DEBUG_BASENAME: os.path.basename(exe.debug_path) if exe else "EXE_DEBUG_BASENAME",
			EXE_DEBUG_RELPATH: os.path.join(".", os.path.relpath(exe.debug_path)) if exe else "EXE_DEBUG_RELPATH",
			EXE_DEBUG_ABSPATH: os.path.abspath(exe.debug_path) if exe else "EXE_DEBUG_ABSPATH",
			LIBC_BASENAME: os.path.basename(libc.path) if libc else "LIBC_BASENAME",
			LIBC_RELPATH: os.path.join(".", os.path.relpath(libc.path)) if libc else "LIBC_RELPATH",
			LIBC_ABSPATH: os.path.abspath(libc.path) if libc else "LIBC_ABSPATH",
			LIBC_DEBUG_BASENAME: os.path.basename(libc.debug_path) if libc else "LIBC_DEBUG_BASENAME",
			LIBC_DEBUG_RELPATH: os.path.join(".", os.path.relpath(libc.debug_path)) if libc else "LIBC_DEBUG_RELPATH",
			LIBC_DEBUG_ABSPATH: os.path.abspath(libc.debug_path) if libc else "LIBC_DEBUG_ABSPATH",
			INTERACTIONS: interactions.dump(self.tab_interactions_placeholder) if interactions else "",
		}

		new_content = self.template_content
		for placeholder, replacement in replacements.items():
			new_content = new_content.replace(placeholder, replacement)

		# Write new script
		if exe: script = script.replace(EXE_BASENAME, os.path.basename(exe.path))
		script = fix_if_exist(script)
		with open(script, "w") as script_file:
			script_file.write(new_content)
		log.success(f"Script \'{script}\' created")
