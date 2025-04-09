from pathlib import Path
import json
import requests
from spwn.file_manage import handle_path, check_file, check_dir
from spwn.args import Args

CONFIG_DIR_PATH = handle_path("~/.config/spwn/")
CONFIG_FILEPATH = CONFIG_DIR_PATH / "config.json"
DEFAULT_CONFIG = {
	"check_functions": ["system", "gets", "ptrace", "memfrob", "strfry", "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe"],
	"patch_path": "./debug/<exe_basename>_patched",
	"seccomp": True,
	"yara_rules": str(CONFIG_DIR_PATH / "findcrypt3.rules"),
	"cwe": False,
	"download_libc_source": False,
	"template_path": str(CONFIG_DIR_PATH / "template.py"),
	"interactions": False,
	"pwntube_variable": "io",
	"tab": "\t",
	"script_path": "solve_<exe_basename>.py",
	"commands": [],
}

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		actual_config = self.read_config_file()

		# Set config variables
		self.check_functions: list[str] = actual_config["check_functions"]
		patch_path: str | None			= args.patch or actual_config["patch_path"]
		self.seccomp: bool				= args.seccomp or actual_config["seccomp"]
		yara_rules: str | None			= args.yara or actual_config["yara_rules"]
		self.cwe: bool					= args.cwe or actual_config["cwe"]
		self.download_libc_source: bool	= args.libc_source or actual_config["download_libc_source"]
		template_path: str | None		= args.template or actual_config["template_path"]
		self.interactions: bool			= args.interactions or actual_config["interactions"]
		self.pwntube_variable: str		= actual_config["pwntube_variable"]
		self.tab: str					= actual_config["tab"]
		script_path: str | None			= actual_config["script_path"]
		self.commands: list[str]		= actual_config["commands"]

		# Handle paths
		self.patch_path: Path | None = handle_path(patch_path)
		self.yara_rules: Path | None = handle_path(yara_rules)
		self.template_path: Path | None = handle_path(template_path)
		self.script_path: Path | None = handle_path(script_path)
		if not self.script_path and self.template_path:
			self.script_path = Path(self.template_path.name)

		# Handle only mode
		if args.only:
			if not args.patch: self.patch_path = None
			if not args.seccomp: self.seccomp = False
			if not args.yara: self.yara_rules = None
			if not args.cwe: self.cwe = False
			if not args.libc_source: self.download_libc_source = False
			if not args.interactions and not args.template: self.template_path = None
			if not args.interactions: self.interactions = False


	def read_config_file(self) -> dict[str]:

		# Check if config file exists
		if not check_file(CONFIG_FILEPATH):

			# If config dir doesn't exists, create it
			if not check_dir(CONFIG_DIR_PATH):
				CONFIG_DIR_PATH.mkdir()

			# Write default config file
			CONFIG_FILEPATH.write_text(json.dumps(DEFAULT_CONFIG, indent='\t'))

			# Try to download missing config files
			def download_config_file(key: str, url: str):
				yara_rules = handle_path(DEFAULT_CONFIG[key])
				if yara_rules and not check_file(yara_rules):
					try:
						response = requests.get(url)
						yara_rules.write_text(response.text)
					except:
						pass
			download_config_file("yara_rules", "https://raw.githubusercontent.com/polymorf/findcrypt-yara/master/findcrypt3.rules")
			download_config_file("template_path", "https://raw.githubusercontent.com/Church-17/spwn/master/resources/template.py")

			actual_config = DEFAULT_CONFIG
		
		else:
			# If config file exists, read it
			actual_config = json.loads(CONFIG_FILEPATH.read_text())

			# Check integrity and restore config file if necessary
			if set(actual_config) != set(DEFAULT_CONFIG):
				actual_config = DEFAULT_CONFIG | actual_config
				CONFIG_FILEPATH.write_text(json.dumps(actual_config, indent='\t'))

		return actual_config
