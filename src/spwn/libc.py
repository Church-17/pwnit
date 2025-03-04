from pwn import log, libcdb
from spwn.binary import Binary
import os
import re


class Libc(Binary):
	def __init__(self, name: str):
		super().__init__(name)

		# Retrieve libc version from libc.rip
		libc_matches = libcdb.query_libc_rip({'buildid': self.buildid.hex()})
		assert len(libc_matches) == 1
		self.libc_version = libc_matches[0]['id']


	@classmethod
	def check_filetype(cls, filepath: str) -> bool:
		match = re.search(r"^libc([^A-Za-z].*)?\.so.*", os.path.basename(filepath))
		if match:
			return True
		return False


	def print_version(self) -> None:
		"""Print the version string or raise a warning"""

		if self.libc_version:
			log.info(f"Libc version: {self.libc_version}")


	def download_libs(self) -> str | None:
		"""Download the required libs around this libc, loader included"""

		with log.progress("Retrieve libs", "Downloading...") as waiting:
			libs_path = libcdb.download_libraries(self.path)
			if libs_path:
				waiting.success("Done!")
			else:
				waiting.failure("Error!")

		return libs_path





	
	def download_source(self, path: str):
		return
