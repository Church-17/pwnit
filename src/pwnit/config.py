from pathlib import Path

from pwnit.file_manage import handle_path, check_file, check_dir, download_file
from pwnit.args import Args
from pwnit.utils import log, choose


CONFIG_DIRPATH: Path = handle_path("~/.config/pwnit/")
CONFIG_FILEPATH = CONFIG_DIRPATH / "config.yml"


class Config:
	def __init__(self, args: Args) -> None:

		# Read and validate config
		config: dict[str] = self.validate_config(self.read_config_file())

		# Retrieve template to use:
		templates: dict = config.get("templates", {})
		template = {}
		if args.template: # if a template is been specified in args, use that if present
			if templates:
				if args.template not in templates:
					log.failure("Speficied template isn't present in the configuration")
					args.template = choose(list(templates), "Choose template to use:")
				template = templates[args.template]
			else:
				log.failure("There are no templates in the configuration")
		elif "default" in templates: # else if a default template is present
			template = templates["default"]
		elif templates: # else if there are some templates in config
			log.warning("Default template isn't present in the configuration")
			template = templates[choose(list(templates), "Choose template to use:")]
		assert isinstance(template, dict)

		# Set config variables
		self.check_functions: list[str] = config.get("check_functions", [])
		self.patch_path: Path | None	= handle_path(args.patch or config.get("patch", None))
		self.seccomp: bool				= args.seccomp or config.get("seccomp", False)
		self.yara_rules: Path | None	= handle_path(args.yara or config.get("yara", None))
		self.libc_source: bool			= args.libc_source or config.get("libc_source", False)
		self.template_path: Path | None	= handle_path(template.get("path", None))
		self.interactions: bool			= args.interactions or template.get("interactions", False)
		self.pwntube_variable: str		= template.get("pwntube_variable", "io")
		self.tab: str					= template.get("tab", "\t")
		self.script_path: Path			= handle_path(template.get("script_path", "solve_<exe_basename:>.py"))
		self.commands: list[str]		= config.get("commands", [])

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
	
	def validate_config(self, config: dict[str]) -> dict[str]:
		"""Validate the schema of the config using cerberus"""

		from importlib import resources
		import json
		import jsonschema

		with resources.open_text('pwnit.schemas', 'config.schema.json') as f:
			schema = json.load(f)

		try:
			jsonschema.validate(config, schema)
		except Exception as err:
			log.failure(f"Invalid config: {err}")
			exit()

		return config
