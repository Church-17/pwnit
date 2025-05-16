import re
from pwnit.file_manage import relative_path
from pwnit.exe import Exe
from pwnit.libc import Libc
from pwnit.interactions import Interactions


def replace_placeholders(
		text: str,
		exe: Exe | None = None,
		libc: Libc | None = None,
		remote: str | None = None,
		interactions: Interactions | None = None,
		keep_missing: bool = True,
	) -> str | None:

	# Handle host and port from remote
	host, port = remote.split(":", 1) if remote else (None, None)

	# Create substitution dictionary
	substitutions: dict[str, str | None] = {
		"exe_basename": exe.path.name if exe else None,
		"exe_relpath": f"{relative_path(exe.path)}" if exe else None,
		"exe_abspath": f"{exe.path.resolve()}" if exe else None,
		"exe_debug_basename": exe.debug_path.name if exe else None,
		"exe_debug_relpath": f"{relative_path(exe.debug_path)}" if exe else None,
		"exe_debug_abspath": f"{exe.debug_path.resolve()}" if exe else None,
		"libc_basename": libc.path.name if libc else None,
		"libc_relpath": f"{relative_path(libc.path)}" if libc else None,
		"libc_abspath": f"{libc.path.resolve()}" if libc else None,
		"libc_debug_basename": libc.debug_path.name if libc else None,
		"libc_debug_relpath": f"{relative_path(libc.debug_path)}" if libc else None,
		"libc_debug_abspath": f"{libc.debug_path.resolve()}" if libc else None,
		"libc_id": libc.libc_id if libc and libc.libc_id else None,
		"libc_version": libc.libc_version if libc and libc.libc_version else None,
		"libc_source_path": f"{libc.source_path}" if libc and libc.source_path else None,
		"remote": remote,
		"host": host,
		"port": port,
		"interactions": interactions,
	}

	# Prepare to replace interactions
	interactions_matches = re.finditer(r"([ \t]*?)(?:#.*?)?<interactions(:.*?)?>", text)

	# Define error when a placeholder is cannot be substituted
	class SubstitutionError(Exception): ...

	# Define the substitution function
	def substitute(re_match: re.Match) -> str:
		placeholder = re_match.group(1)

		# If the found regex is a correct placeholder
		if placeholder in substitutions:

			# If placeholder can be substitute with a good value, return it
			if substitutions[placeholder]:

				# Handle tabs before interactions tag
				if placeholder == "interactions":
					nonlocal interactions_matches
					return interactions.dump(next(interactions_matches).group(1))
					
				return substitutions[placeholder]

			# If there is an integrated default, use it
			elif re_match.group(2): return re_match.group(2)[1:]

			# If the missing can't be kept, raise an error to stop the substitutions
			elif not keep_missing: raise SubstitutionError
		
		# If the found regex is not a correct placeholder, or the missing can be kept, don't do anything
		return re_match.group(0)

	# Substitute placeholders handling substitution error
	try:
		new_text = re.sub(r"<(.*?)(:.*?)?>", substitute, text)
	except SubstitutionError:
		return None

	return new_text
