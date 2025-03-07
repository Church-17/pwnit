import re
import os
from spwn.binary import Binary

class Loader(Binary):
	def __init__(self, name: str):
		super().__init__(name)


	@classmethod
	def check_filetype(cls, filepath: str) -> bool:
		match = re.search(r"^ld([^A-Za-z].*)?\.so.*", os.path.basename(filepath))
		if match:
			return True
		return False
