from pathlib import Path
from pwnit.file_manage import handle_path, check_file, check_dir, download_file
from pwnit.args import Args
from pwnit.utils import log, choose

CONFIG_DIRPATH: Path = handle_path("~/.config/pwnit/")
CONFIG_FILEPATH = CONFIG_DIRPATH / "config.yml"

class Config:
	def __init__(self, args: Args) -> None:

		# Read and validate config
		config = self.validate_config(self.read_config_file())

		# Retrieve template to use
		if args.template:
			if args.template not in config["templates"]:
				log.error("Speficied template isn't present in the configuration")
			template = config["templates"][args.template]
		elif "default" in config["templates"]:
			template = config["templates"]["default"]
		elif config["templates"]:
			log.warning("Default template isn't present in the configuration")
			template = config["templates"][choose(list(config["templates"]), "Choose template to use:")]
		else:
			template = None

		# Set config variables
		self.check_functions: list[str] = config["check_functions"]["list"] if config["check_functions"]["enable"] else []
		self.patch_path: Path | None	= handle_path(config["patch"]["path"]) if args.patch or config["patch"]["enable"] else None
		self.seccomp: bool				= True if args.seccomp or config["seccomp"]["enable"] else False
		self.yara_rules: Path | None	= handle_path(config["yara"]["path"]) if args.yara or config["yara"]["enable"] else None
		self.libc_source: bool			= True if args.libc_source or config["libc_source"]["enable"] else False
		self.template_path: Path | None	= handle_path(template["path"]) if template else None
		self.interactions: bool			= args.interactions or template["interactions"]
		self.pwntube_variable: str		= template["pwntube_variable"]
		self.tab: str					= template["tab"]
		self.script_path: str | None	= handle_path(template["script_path"])
		self.commands: list[str]		= config["commands"]

		# Handle only mode
		if args.only:
			if not args.patch: self.patch_path = None
			if not args.seccomp: self.seccomp = False
			if not args.yara: self.yara_rules = None
			if not args.libc_source: self.libc_source = False
			if not args.interactions and not args.template: self.template_path = None
			if not args.interactions: self.interactions = False
			self.commands = []


	def read_config_file(self) -> dict[str]:
		import yaml

		# Check if config file exists
		if not check_file(CONFIG_FILEPATH):

			# If config dir doesn't exists, create it
			if not check_dir(CONFIG_DIRPATH):
				CONFIG_DIRPATH.mkdir()

			# Try to download missing config files
			download_file(handle_path(CONFIG_FILEPATH), "https://raw.githubusercontent.com/Church-17/pwnit/master/resources/config.yml")
			download_file(handle_path(CONFIG_DIRPATH / "findcrypt3.rules"), "https://raw.githubusercontent.com/polymorf/findcrypt-yara/master/findcrypt3.rules")
			download_file(handle_path(CONFIG_DIRPATH / "template.py"), "https://raw.githubusercontent.com/Church-17/pwnit/master/resources/template.py")

		# Parse config file
		with open(CONFIG_FILEPATH, "r") as config_file:
			config = yaml.safe_load(config_file)

		return config
	
	def validate_config(self, config):
		import cerberus

		CONFIG_SCHEMA = {
			"check_functions": {"type": "dict", "default": {}, "schema": {
				"enable": {"type": "boolean", "default": False},
				"list": {"type": "list", "default": [], "schema": {"type": "string"}},
			}},
			"patch": {"type": "dict", "default": {}, "schema": {
				"enable": {"type": "boolean", "default": False},
				"path": {"type": "string", "default": ""},
			}},
			"seccomp": {"type": "dict", "default": {}, "schema": {
				"enable": {"type": "boolean", "default": False},
			}},
			"yara": {"type": "dict", "default": {}, "schema": {
				"enable": {"type": "boolean", "default": False},
				"path": {"type": "string", "default": ""},
			}},
			"libc_source": {"type": "dict", "default": {}, "schema": {
				"enable": {"type": "boolean", "default": False},
			}},
			"templates": {"type": "dict", "default": {}, "keysrules": {"type": "string"}, "valuesrules": {
				"type": "dict", "schema": {
					"path": {"type": "string", "default": ""},
					"interactions": {"type": "boolean", "default": False},
					"pwntube_variable": {"type": "string", "default": "io"},
					"tab": {"type": "string", "default": "\t"},
					"script_path": {"type": "string", "default": "solve_<exe_basename:>.py"},
				},
			}},
			"commands": {"type": "list", "default": [], "schema": {"type": "string"}}
		}

		validator = cerberus.Validator(CONFIG_SCHEMA)
		config = validator.normalized(config)
		is_valid = validator(config)
		if not is_valid:
			log.error(f"Configuration not valid:\n{validator.errors}")

		return config 
