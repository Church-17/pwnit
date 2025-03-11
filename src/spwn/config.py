import json
import os
import requests
from spwn.args import Args

CONFIG_DIR_PATH = os.path.expanduser("~/.config/spwn")
CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
	"download_libc_source": False,
	"check_functions": ["system", "gets", "ptrace", "memfrob", "strfry", "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe"],
	"patch_path": "./debug/<exe_basename>_patched",
	"seccomp": True,
	"yara_rules": os.path.join(CONFIG_DIR_PATH, "findcrypt3.rules"),
	"cwe": False,
	"template_file": os.path.join(CONFIG_DIR_PATH, "template.py"),
	"interactions": False,
	"pwntube_variable": "io",
	"tab": "\t",
	"script_basename": "solve_<exe_basename>.py",
}

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		actual_config = self.read_config_file()

		# Set config variables
		self.download_libc_source: bool	= args.source or actual_config["download_libc_source"]
		self.check_functions: list[str] = actual_config["check_functions"]
		self.patch_path: str | None		= args.patch or actual_config["patch_path"]
		self.seccomp: bool				= args.seccomp or actual_config["seccomp"]
		self.yara_rules: str | None		= args.yara or actual_config["yara_rules"]
		self.cwe: bool					= args.cwe or actual_config["cwe"]
		self.template_file: str | None	= args.template or actual_config["template_file"]
		self.interactions: bool			= args.interactions or actual_config["interactions"]
		self.pwntube_variable: str		= actual_config["pwntube_variable"]
		self.tab: str					= actual_config["tab"]
		self.script_basename: str		= actual_config["script_basename"]

		# Handle only mode
		if args.only:
			if not args.source: self.download_libc_source = False
			if not args.patch: self.patch_path = None
			if not args.seccomp: self.seccomp = False
			if not args.yara: self.yara_rules = None
			if not args.cwe: self.cwe = False
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

			# If config dir doesn't exists, create it
			if not os.path.isdir(config_dir_path):
				os.makedirs(config_dir_path, exist_ok=True)

			with open(config_file_path, "w") as file:
				json.dump(DEFAULT_CONFIG, file, indent='\t')

			if not os.path.isfile(DEFAULT_CONFIG["yara_rules"]):
				response = requests.get("https://raw.githubusercontent.com/polymorf/findcrypt-yara/master/findcrypt3.rules")
				if response:
					with open(DEFAULT_CONFIG["yara_rules"], "w") as yara_file:
						yara_file.write(response.text)

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
