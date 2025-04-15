from pathlib import Path
import re
from spwn.utils import log
from spwn.file_manage import check_file
from spwn.exe import Exe
from spwn.libc import Libc
from spwn.interactions import Interactions
from spwn.placeholders import replace_placeholders


def create_script(
		template_path: Path,
		script_path: Path,
		remote: str | None = None,
		exe: Exe | None = None,
		libc: Libc | None = None,
		interactions: Interactions | None = None,
	) -> None:

	# Handle placeholders in script path
	script_path = Path(replace_placeholders(f"{script_path}", exe, libc, remote))

	# Read template file (or script file if already exists)
	if check_file(script_path):
		content = script_path.read_text()
	elif check_file(template_path):
		content = template_path.read_text()
	else:
		log.failure("There is neither a template file nor a script file. A new script will not be created")
		return

	# Search for spaces before interactions
	match = re.search(r"([ \t]*)(?:#[ \t]*)?<interactions(?:(:)(.*?))?>", content)
	tab_interactions_placeholder: str = match.group(1) if match else ""

	# Replace placeholders
	new_content = replace_placeholders(
		content,
		exe,
		libc,
		remote,
		interactions.dump(tab_interactions_placeholder) if interactions else None,
	)

	# Write new script
	script_path.write_text(new_content)
	log.success(f"Script \'{script_path}\' updated")
