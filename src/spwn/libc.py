from pathlib import Path
import re
import tarfile
import requests
from pwn import libcdb
from spwn.utils import log, log_silent
from spwn.file_manage import handle_path, check_dir
from spwn.binary import Binary


class Libc(Binary):
	def __init__(self, filepath: Path) -> None:
		super().__init__(filepath)
		self.source_path: Path | None = None

		# Retrieve libc id
		with log.progress("Libc version", "Retrieving libc ID from libc.rip...") as progress:
			with log_silent:
				libc_matches = libcdb.query_libc_rip({'buildid': self.buildid.hex()})
			if libc_matches:
				self.libc_id = libc_matches[0]['id']

				# Retrieve libc version
				match = re.search(r"\d+(?:\.\d+)+", self.libc_id)
				assert match
				self.libc_version = match.group()

			else:
				self.libc_id = None
				progress.status("Failed to retrieve libc ID from libc.rip, retrieving version from file...")
				if libc_matches == []:
					log.warning(f"Recognized libc is not a standard libc")

				# Retrieve libc version
				match = re.search(br"release version (\d+(?:\.\d+)+)", self.path.read_bytes())
				if match:
					self.libc_version = match.group(1).decode()
				else:
					self.libc_version = None
					progress.failure("Failed to retrieve libc version")

			# Print libc version and id
			if self.libc_version:
				progress.success(f"{self.libc_version}" + (f" ({self.libc_id})" if self.libc_id else ""))

		# Download libs
		with log.progress("Retrieve libs", "Downloading...") as progress:
			with log_silent:
				try:
					self.libs_path = handle_path(libcdb.download_libraries(self.path))
				except requests.RequestException:
					self.libs_path = None
			if self.libs_path:
				progress.success(f"Done ({self.libs_path})")
			else:
				progress.failure("Failed to download libs")


	def download_source(self) -> None:
		"""Download the source code of this libc version"""

		with log.progress("Libc source") as progress:

			# Check numeric libc version
			if not self.libc_version:
				progress.failure("Missing libc version")
				return
			
			# Handle cache dir
			cache_dir = Path("~/.cache/spwn").expanduser()
			if not check_dir(cache_dir):
				cache_dir.mkdir()

			# Check cached libc sources
			source_dirname = f"glibc-{self.libc_version}"
			for cached_source in cache_dir.iterdir():
				if source_dirname == cached_source.name:
					break

			else:
				# Get libc source archive
				url = f"http://ftpmirror.gnu.org/gnu/libc/{source_dirname}.tar.gz"
				progress.status(f"Downloading from {url}...")
				try:
					response = requests.get(url)
				except requests.RequestException:
					response = None
				if not response:
					progress.failure(f"Download from {url} failed")
					return None
				archive_path = Path(f"/tmp/{source_dirname}.tar.gz")
				archive_path.write_bytes(response.content)

				# Extract archive
				progress.status("Extracting...")
				with tarfile.open(archive_path, "r:gz") as tar:
					tar.extractall(cache_dir)

			# Return libc source
			self.source_path = cache_dir / source_dirname
			progress.success(f"{self.source_path}")
