import os
from pwn import ELF

class Binary(ELF):
	def __init__(self, filepath: str) -> None:
		super().__init__(os.path.expanduser(filepath), checksec=False)
		self.debug_path: str = self.path

	def set_executable(self) -> None:
		os.chmod(self.path, 0o755)
		if self.debug_path != self.path:
			os.chmod(self.debug_path, 0o755)
