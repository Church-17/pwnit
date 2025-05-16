from pathlib import Path
from pwnit.file_manage import handle_path, check_file, check_dir, download_file
from pwnit.args import Args

CONFIG_DIRPATH: Path = handle_path("~/.config/pwnit/")
CONFIG_FILEPATH = CONFIG_DIRPATH / "config.yml"

class Config:
	def __init__(self, args: Args) -> None:

		# Read (and create if necessary) the config
		config = self.read_config_file()

		# Set config variables
		self.check_functions: list[str] = config["check_functions"].get("list", []) if config["check_functions"]["enable"] else []
		self.patch_path: Path | None	= handle_path(config["patch"]["path"]) if args.patch or config["patch"]["enable"] else None
		self.seccomp: bool				= True if args.seccomp or config["seccomp"]["enable"] else False
		self.yara_rules: Path | None	= handle_path(config["yara"]["path"]) if args.yara or config["yara"]["enable"] else None
		self.libc_source: bool			= True if args.libc_source or config["libc_source"]["enable"] else False
		self.commands: list[str]		= config.get("commands", [])

		template: dict[str] | None		= config["templates"].get(args.template or "default", None)
		if template:
			self.template_path: Path | None	= handle_path(template["path"])
			self.interactions: bool			= args.interactions or template["interactions"]
			self.pwntube_variable: str		= template["pwntube_variable"]
			self.tab: str					= template["tab"]
			self.script_path: str | None	= handle_path(template["script_path"])

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

		# TODO: check integrity

		return config
