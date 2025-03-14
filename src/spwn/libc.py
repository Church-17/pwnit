from pathlib import Path
import re
import tarfile
from urllib.parse import urlparse
import requests
from pwn import log, libcdb, context
from spwn.file_manage import handle_path
from spwn.binary import Binary


class Libc(Binary):
	def __init__(self, filepath: Path):
		super().__init__(filepath)

		# Retrieve libc id
		with log.progress("Libc version", "Retrieving libc ID from libc.rip...") as waiting:
			with context.silent:
				libc_matches = libcdb.query_libc_rip({'buildid': self.buildid.hex()})
			if libc_matches:
				self.libc_id = libc_matches[0]['id']

				# Retrieve libc version
				match = re.search(r"\d+(?:\.\d+)+", self.libc_id)
				assert match
				self.libc_version = match.group()

			else:
				self.libc_id = None
				waiting.status("Failed to retrieve libc ID from libc.rip, retrieving version from file...")
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
					waiting.failure("Failed to retrieve libc version")

			# Print libc version and id
			if self.libc_version:
				waiting.success(f"{self.libc_version}" + (f" ({self.libc_id})" if self.libc_id else ""))

		# Download libs
		with log.progress("Retrieve libs", "Downloading...") as waiting:
			with context.silent:
				try:
					self.libs_path = handle_path(libcdb.download_libraries(self.path))
				except requests.RequestException:
					self.libs_path = None
			if self.libs_path:
				waiting.success(f"Done ({self.libs_path})")
			else:
				waiting.failure("Failed to download libs")


	def download_source(self, dirpath: Path = Path.cwd()) -> None:
		"""Download the source code of this libc version"""

		with log.progress("Libc source") as waiting:

			# Get numeric libc version
			if not self.libc_version:
				waiting.failure("Libc version absent")
				return

			# Get libc source archive
			url = f"http://ftpmirror.gnu.org/gnu/libc/glibc-{self.libc_version}.tar.gz"
			waiting.status(f"Downloading from {url}...")
			try:
				response = requests.get(url)
			except requests.RequestException:
				response = None
			if not response:
				waiting.failure(f"Download from {url} failed")
				return None
			archive_path = Path(f"/tmp/{urlparse(url).path.rsplit("/", 1)[-1]}")
			archive_path.write_bytes(response.content)

			# Extract archive
			waiting.status("Extracting...")
			with tarfile.open(archive_path, "r:gz") as tar:
				tar.extractall(dirpath)

			waiting.success()
