import json
import os
from spwn.args import Args

CONFIG_DIR_PATH = os.path.expanduser("./config_dir")
CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
	"debug_dir": "debug",
	"script_basename": "solve_<exe_basename>.py",
	"pwntube_variable": "io",
	"tab": "\t",
	"check_functions": ["system", "gets", "ptrace", "memfrob", "strfry", "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe"],
	"yara_rules": "~/.config/spwn/findcrypt3.rules",
	"cwe": False,
	"patch": "<exe_basename>_patched",
	"download_libc_source": False,
	"template_file": "~/.config/spwn/template.py",
	"interactions": False,
}

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		actual_config = self.read_config_file()

		# Set config variables 
		self.debug_dir: str					= actual_config["debug_dir"]
		self.script_basename: str			= actual_config["script_basename"]
		self.pwntube_variable: str			= actual_config["pwntube_variable"]
		self.tab: str						= actual_config["tab"]
		self.check_functions: list[str] 	= actual_config["check_functions"]
		self.yara_rules: str | None			= args.yara or actual_config["yara_rules"]
		self.cwe: bool						= args.cwe or actual_config["cwe"]
		self.patch: str | None				= args.patch or actual_config["patch"]
		self.download_libc_source: bool		= args.source or actual_config["download_libc_source"]
		self.template_file: str | None		= args.template or actual_config["template_file"]
		self.interactions: bool				= args.interactions or actual_config["interactions"]

		# Handle only mode
		if args.only:
			if not args.yara: self.yara_rules = None
			if not args.cwe: self.cwe = False
			if not args.patch: self.patch = None
			if not args.source: self.download_libc_source = False
			if not args.interactions and not args.template: self.template_file = None
			if not args.interactions: self.interactions = False

		# Handle specific config
		if self.yara_rules: self.yara_rules = os.path.expanduser(self.yara_rules)
		if self.template_file: self.template_file = os.path.expanduser(self.template_file)


	def read_config_file(self) -> dict[str]:
		# Config file variables
		config_dir_path = CONFIG_DIR_PATH
		config_file_path = os.path.join(CONFIG_DIR_PATH, CONFIG_FILENAME)

		# Check if config file exists
		if not os.path.isfile(config_file_path):

			# If config file doesn't exists, create it
			if not os.path.isdir(config_dir_path):
				os.makedirs(config_dir_path, exist_ok=True)
			with open(config_file_path, "w") as file:
				json.dump(DEFAULT_CONFIG, file, indent='\t')

			actual_config = DEFAULT_CONFIG
		
		else:
			# If config file exists, read it
			with open(config_file_path) as file:
				actual_config = json.load(file)

			# Check integrity and restore config file if necessary
			if set(actual_config) != set(DEFAULT_CONFIG):
				actual_config = DEFAULT_CONFIG | actual_config
				with open(config_file_path, "w") as file:
					json.dump(actual_config, file, indent='\t')

		return actual_config
