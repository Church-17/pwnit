from pathlib import Path
from pwnit.utils import log
from pwnit.file_manage import check_file
from pwnit.exe import Exe
from pwnit.libc import Libc
from pwnit.interactions import Interactions
from pwnit.placeholders import replace_placeholders


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

	# Replace placeholders
	new_content = replace_placeholders(content, exe, libc, remote, interactions)

	# Write new script
	script_path.write_text(new_content)
	log.success(f"Script \'{script_path}\' updated")
