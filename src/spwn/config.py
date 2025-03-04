import os
import json
from spwn.args import Args

CONFIG_DIR_PATH = os.path.expanduser("./config_dir")
CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
	"debug_dir": "debug_dir",
	"solve_filename": "a.py",
	"pwn_process": "r",
	"tab": "\t",
	"template_file": "~/.config/spwn/template.py",
}

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		actual_config = self.read_config_file()

		self.debug_dir = actual_config["debug_dir"]
		self.template_file = actual_config["template_file"]
		self.solve_filename = actual_config["solve_filename"]
		self.tab = actual_config["tab"]


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
