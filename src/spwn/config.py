import os
import json
from spwn.args import Args

CONFIG_DIR_PATH = os.path.expanduser("./config_dir")
CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
	"debug_dir": "debug",
	"dangerous_functions": ["system", "gets", "ptrace", "memfrob", "strfry", "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe"],
	"analyze_seccomp": True,
	"yara_rules": "~/.config/spwn/findcrypt3.rules",
	"analyze_cwe": False,
	"download_libc_source": False,
	"patch_basename": "{exe_basename}_patched",
	"do_interactions": False,
	"template_file": "~/.config/spwn/template.py",
	"script_basename": "solve_{exe_basename}.py",
	"pwntube_variable": "io",
	"tab": "\t",
}

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		actual_config = self.read_config_file()

		self.debug_dir: str					= actual_config["debug_dir"]
		self.dangerous_functions: list[str] = actual_config["dangerous_functions"]
		self.analyze_seccomp: bool			= actual_config["analyze_seccomp"]
		self.yara_rules: str | None			= os.path.expanduser(actual_config["yara_rules"])
		self.analyze_cwe: bool				= actual_config["analyze_cwe"]
		self.download_libc_source			= args.source or actual_config["download_libc_source"]
		self.patch_basename: str | None		= actual_config["patch_basename"]
		self.do_interactions: bool			= args.interactions or actual_config["do_interactions"]
		self.template_file: str | None		= os.path.expanduser(args.template or actual_config["template_file"])
		self.script_basename: str			= actual_config["script_basename"]
		self.pwntube_variable: str			= actual_config["pwntube_variable"]
		self.tab: str						= actual_config["tab"]


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
