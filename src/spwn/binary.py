import os
from pwn import ELF, log

class Binary(ELF):
	def __init__(self, filepath: str) -> None:
		super().__init__(os.path.expanduser(filepath), checksec=False)
		self.debug_path: str = self.path
		log.info(f"{type(self).__name__}: {self.path}")
