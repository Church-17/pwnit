from spwn.file_manage import relative_path
from spwn.exe import Exe
from spwn.libc import Libc


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
LIBC_ID = "<libc_id>"
LIBC_VERSION = "<libc_version>"
LIBC_SOURCE_PATH = "<libc_source_path>"
REMOTE = "<remote>"
HOST = "<host>"
PORT = "<port>"
INTERACTIONS = "<interactions>"


def replace_placeholders(
		text: str,
		exe: Exe | None = None,
		libc: Libc | None = None,
		remote: str | None = None,
		interactions: str | None = None,
		use_defaults: bool = True,
	) -> str | None:

	# Handle host and port from remote
	host, port = remote.split(":", 1) if remote and ":" in remote else (None, None)

	substitutions: dict[str, tuple[str | None, str]] = {
		EXE_BASENAME: (exe.path.name if exe else None, "EXE_BASENAME"),
		EXE_RELPATH: (f"{relative_path(exe.path)}" if exe else None, "EXE_RELPATH"),
		EXE_ABSPATH: (f"{exe.path.resolve()}" if exe else None, "EXE_ABSPATH"),
		EXE_DEBUG_BASENAME: (exe.debug_path.name if exe else None, "EXE_DEBUG_BASENAME"),
		EXE_DEBUG_RELPATH: (f"{relative_path(exe.debug_path)}" if exe else None, "EXE_DEBUG_RELPATH"),
		EXE_DEBUG_ABSPATH: (f"{exe.debug_path.resolve()}" if exe else None, "EXE_DEBUG_ABSPATH"),
		LIBC_BASENAME: (libc.path.name if libc else None, "LIBC_BASENAME"),
		LIBC_RELPATH: (f"{relative_path(libc.path)}" if libc else None, "LIBC_RELPATH"),
		LIBC_ABSPATH: (f"{libc.path.resolve()}" if libc else None, "LIBC_ABSPATH"),
		LIBC_DEBUG_BASENAME: (libc.debug_path.name if libc else None, "LIBC_DEBUG_BASENAME"),
		LIBC_DEBUG_RELPATH: (f"{relative_path(libc.debug_path)}" if libc else None, "LIBC_DEBUG_RELPATH"),
		LIBC_DEBUG_ABSPATH: (f"{libc.debug_path.resolve()}" if libc else None, "LIBC_DEBUG_ABSPATH"),
		LIBC_ID: (libc.libc_id if libc and libc.libc_id else None, "LIBC_ID"),
		LIBC_VERSION: (libc.libc_version if libc and libc.libc_version else None, "LIBC_VERSION"),
		LIBC_SOURCE_PATH: (f"{libc.source_path}" if libc and libc.source_path else None, "LIBC_SOURCE_PATH"),
		REMOTE: (remote, "REMOTE"),
		HOST: (host, "HOST"),
		PORT: (port, "PORT"),
		INTERACTIONS: (interactions, ""),
	}

	for placeholder, (value, default) in substitutions.items():
		if placeholder in text:
			if value: text = text.replace(placeholder, value)
			elif use_defaults: text = text.replace(placeholder, default)
			else: return None

	return text
