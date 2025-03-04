from pwn import ELF
import os
import re
from spwn.utils import run_command

class Binary(ELF):
	def __init__(self, filepath: str):
		super().__init__(os.path.expanduser(filepath), checksec=False)
		self.debug_path: str = self.path

	@classmethod
	def check_filetype(cls, filepath: str) -> bool:
		"""Check if a file is an executable"""

		filecmd_output = run_command(["file", "-bL", filepath], timeout=1)
		if filecmd_output:
			match = re.search(r"^ELF ", filecmd_output)
			if match:
				return True
		return False
