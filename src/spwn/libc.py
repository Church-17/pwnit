from pwn import log, libcdb, context
from spwn.binary import Binary
import os
import re
import requests
import tarfile


class Libc(Binary):
	def __init__(self, name: str):
		super().__init__(name)
		self.libc_version = self.get_libc_version()


	@classmethod
	def check_filetype(cls, filepath: str) -> bool:
		match = re.search(r"^libc([^A-Za-z].*)?\.so.*", os.path.basename(filepath))
		if match:
			return True
		return False


	def get_libc_version(self) -> str | None:
		try:
			libc_matches = libcdb.query_libc_rip({'buildid': self.buildid.hex()})
			return libc_matches[0]['id']
		except:
			with open(self.path, "br") as libc_file:
				libc_content = libc_file.read()
			match = re.search(br"release version (\d+(?:\.\d+)+)", libc_content)
			if match:
				return match.group(1).decode()
		return None


	def print_version(self) -> None:
		"""Print the version string or raise a warning"""

		if self.libc_version:
			log.info(f"Libc version: {self.libc_version}")


	def download_libs(self) -> str | None:
		"""Download the required libs around this libc, loader included"""

		with log.progress("Retrieve libs", "Downloading...") as waiting:
			with context.silent:
				libs_path = libcdb.download_libraries(self.path)
			if libs_path:
				waiting.success()
			else:
				waiting.failure()

		return libs_path


	def download_source(self, dirpath: str) -> None:
		with log.progress("Libc source") as waiting:

			# Get numeric libc version
			if not self.libc_version:
				waiting.failure("Libc version absent")
				return
			match = re.search(r"\d+(?:\.\d+)+", self.libc_version)
			if not match:
				waiting.failure("Libc version absent")
				return

			# Get libc source archive
			url = f"http://ftpmirror.gnu.org/gnu/libc/glibc-{match.group()}.tar.gz"
			waiting.status(f"Downloading from {url}...")
			try:
				response = requests.get(url)
			except requests.ConnectionError as err:
				log.debug(err)
				response = None
			if not response:
				waiting.failure("Download failed")
				return None
			archive_path = os.path.join(dirpath, os.path.basename(url))
			with open(archive_path, "bw") as archive:
				archive.write(response.content)
			
			# Extract
			waiting.status("Extracting...")
			with tarfile.open(archive_path, "r:gz") as tar:
				tar.extractall(dirpath)

			waiting.success()
