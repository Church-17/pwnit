import os
import json
from spwn.args import Args

CONFIG_DIR_PATH = os.path.expanduser("./config_dir")
CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
	"debug_dir": "debug",
	"check_functions": ["system", "gets", "ptrace", "memfrob", "strfry", "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe"],
	"seccomp": True,
	"yara": "~/.config/spwn/findcrypt3.rules",
	"cwe": False,
	"download_libc_source": False,
	"patch": "{exe_basename}_patched",
	"interactions": False,
	"template_file": "~/.config/spwn/template.py",
	"script_basename": "solve_{exe_basename}.py",
	"pwntube_variable": "io",
	"tab": "\t",
}

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		actual_config = self.read_config_file()

		# Handle only mode
		if args.only:
			actual_config["check_functions"] = []
			actual_config["seccomp"] = False
			actual_config["yara"] = None
			actual_config["cwe"] = False
			actual_config["download_libc_source"] = False
			actual_config["patch"] = None
			actual_config["interactions"] = False
			if not args.interactions: actual_config["template_file"] = None

		# Set config variables
		self.check_functions: list[str] 	= actual_config["check_functions"]
		self.seccomp: bool					= actual_config["seccomp"]
		self.yara: str | None				= actual_config["yara"]
		self.cwe: bool						= actual_config["cwe"]
		self.download_libc_source: bool		= args.source or actual_config["download_libc_source"]
		self.patch: str | None				= actual_config["patch"]
		self.interactions: bool				= args.interactions or actual_config["interactions"]
		self.template_file: str | None		= actual_config["template_file"]

		self.debug_dir: str					= actual_config["debug_dir"]
		self.script_basename: str			= actual_config["script_basename"]
		self.pwntube_variable: str			= actual_config["pwntube_variable"]
		self.tab: str						= actual_config["tab"]

		# Handle tilde in paths
		if self.template_file: self.template_file = os.path.expanduser(self.template_file)
		if self.yara: self.yara = os.path.expanduser(self.yara)



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
