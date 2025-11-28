from pathlib import Path
import re
import tarfile
import requests
from pwn import libcdb
from pwnit.utils import log, log_silent, connection
from pwnit.file_manage import handle_path, check_dir, download_file
from pwnit.binary import Binary


class Libc(Binary):
	def __init__(self, filepath: Path) -> None:
		super().__init__(filepath)

		# Initialize variables
		self.source_path: Path | None = None
		self.libc_id: str | None = None
		self.libc_version: str | None = None
		self.libs_path = None

		# Retrieve libc_id
		with log.progress("Libc version", "Retrieving libc ID from libc.rip...") as progress:
			if connection:
				with log_silent:
					libc_matches = libcdb.query_libc_rip({'buildid': self.buildid.hex()})
			else:
				libc_matches = None

			if libc_matches:
				self.libc_id: str = libc_matches[0]['id']

				# Retrieve libc version from libc_id
				progress.status("Retrieving libc version from libc_id...")
				match = re.search(r"\d+(?:\.\d+)+", self.libc_id)
				if match:
					self.libc_version = match.group()

			if not self.libc_version:
				if libc_matches == []:
					log.warning("Recognized libc is not a standard libc")

				# Retrieve libc version
				progress.status("Retrieving libc version from file...")
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
		with log.progress("Retrieve associated libs", "Downloading...") as progress:
			with log_silent:
				try:
					self.libs_path = handle_path(libcdb.download_libraries(self.path))
				except requests.RequestException:
					pass
			if self.libs_path:
				progress.success(f"Done ({self.libs_path})")
			else:
				progress.failure("Failed to download libs")


	def download_source(self) -> None:
		"""Download the source code of this libc version"""

		with log.progress("Download libc source code") as progress:

			# Check numeric libc version
			if not self.libc_version:
				progress.failure("Missing libc version")
				return
			
			# Handle cache dir
			cache_dir = Path("~/.cache/pwnit").expanduser()
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
				archive_path = Path(f"/tmp/{source_dirname}.tar.gz")
				progress.status(f"Downloading from {url}...")
				download_file(archive_path, url)
				if not archive_path.is_file():
					progress.failure(f"Download from {url} failed")
					return

				# Extract archive
				progress.status("Extracting...")
				with tarfile.open(archive_path, "r:gz") as tar:
					tar.extractall(cache_dir)

			# Return libc source
			self.source_path = cache_dir / source_dirname
			progress.success(f"{self.source_path}")
