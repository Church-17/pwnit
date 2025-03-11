import re
import os
import tarfile
import requests
from pwn import log, libcdb, context
from spwn.binary import Binary


class Libc(Binary):
	def __init__(self, name: str):
		super().__init__(name)

		# Retrieve libc id
		libc_matches = libcdb.query_libc_rip({'buildid': self.buildid.hex()})
		if libc_matches:
			self.libc_id = libc_matches[0]['id']

			# Retrieve libc version
			match = re.search(r"\d+(?:\.\d+)+", self.libc_id)
			assert match
			self.libc_version = match.group()

		else:
			self.libc_id = None
			if libc_matches == []:
				log.warning(f"Recognized libc is not a standard libc")

			# Retrieve libc version
			with open(self.path, "br") as libc_file:
				libc_content = libc_file.read()
			match = re.search(br"release version (\d+(?:\.\d+)+)", libc_content)
			if match:
				self.libc_version = match.group(1).decode()
			else:
				self.libc_version = None
				log.warning("Libc version not found in the file")

		# Print libc version and id
		if self.libc_version:
			log.info(f"Libc version: {self.libc_version}" + (f" ({self.libc_id})" if self.libc_id else ""))

		# Download libs
		with log.progress("Retrieve libs", "Downloading...") as waiting:
			with context.silent:
				self.libs_path = libcdb.download_libraries(self.path)
			if self.libs_path:
				waiting.success(f"Done ({self.libs_path})")
			else:
				waiting.failure()


	def download_source(self, dirpath: str = ".") -> None:
		"""Download the source code of this libc version"""
		# TODO thread and cache

		with log.progress("Libc source") as waiting:

			# Get numeric libc version
			if not self.libc_version:
				waiting.failure("Libc version absent")
				return

			# Get libc source archive
			url = f"http://ftpmirror.gnu.org/gnu/libc/glibc-{self.libc_version}.tar.gz"
			waiting.status(f"Downloading from {url}...")
			response = requests.get(url)
			if not response:
				waiting.failure(f"Download from {url} failed")
				return None
			archive_path = os.path.join("/tmp", os.path.basename(url))
			with open(archive_path, "bw") as archive:
				archive.write(response.content)

			# Extract archive
			waiting.status("Extracting...")
			with tarfile.open(archive_path, "r:gz") as tar:
				tar.extractall(dirpath)

			waiting.success()
