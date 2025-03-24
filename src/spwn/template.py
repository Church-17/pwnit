from pathlib import Path
import re
from spwn.utils import log
from spwn.file_manage import fix_if_exist
from spwn.exe import Exe
from spwn.libc import Libc
from spwn.interactions import Interactions
from spwn.placeholders import INTERACTIONS, replace_placeholders


def create_script(
		template: Path,
		script: Path,
		remote: str | None = None,
		exe: Exe | None = None,
		libc: Libc | None = None,
		interactions: Interactions | None = None,
	) -> None:

	# Check template file
	if not template.is_file():
		log.failure("Template file doesn't exists. A new script will not be created")
		return

	# Read template file
	template_content = template.read_text()

	# Search of tabs before interactions
	match = re.search(rf"([ \t]*){INTERACTIONS}", template_content)
	tab_interactions_placeholder: str = match.group(1) if match else ""

	# Replace placeholders
	new_content = replace_placeholders(
		template_content,
		exe,
		libc,
		remote,
		interactions.dump(tab_interactions_placeholder) if interactions else None,
	)

	# Write new script
	script = fix_if_exist(Path(replace_placeholders(f"{script}", exe, libc, remote)))
	script.write_text(new_content)
	log.success(f"Script \'{script}\' created")
