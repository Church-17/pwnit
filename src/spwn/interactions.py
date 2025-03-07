from spwn.utils import ask


class Interactions:
	def __init__(self, pwntube_variable: str, tab: str):
		self.pwntube_variable = pwntube_variable
		self.tab = tab
		self.functions: list[InteractionFunction] = []

		# Menu recvuntil
		self.menu_recvuntil = ask("Menu recvuntil (empty to skip interactions)")
		if not self.menu_recvuntil: return

		# Functions
		while True:
			function_name = ask("Function name (empty to finish interactions)")
			if not function_name: break
			self.functions.append(InteractionFunction(function_name))

	def dump(self, tab_placeholder: str):
		result = f"\n\n{tab_placeholder}".join([
			func.dump(self.pwntube_variable, self.menu_recvuntil, tab_placeholder+self.tab)
			for func in self.functions
		])
		return result


class InteractionFunction:
	def __init__(self, name: str):
		self.name = name
		self.arguments: list[Argument] = []
		
		# Option number
		self.option_number = ask("Option number", can_skip=False)
			
		# Arguments
		while True:
			argument_name = ask("Argument name (empty to end function)")
			if not argument_name: break
			argument_sendafter = ask("Send after", can_skip=False)
			self.arguments.append(Argument(argument_name, argument_sendafter))

	def dump(self, pwntube_variable: str, menu_recvuntil: str, tab: str):
		result = "\n".join([
			f'def {self.name}({", ".join(arg.name for arg in self.arguments)}):',
			f'{tab}{pwntube_variable}.sendlineafter(b"{menu_recvuntil}", b"{self.option_number}")',
		] + [
			f'{tab}{pwntube_variable}.sendlineafter(b"{arg.sendafter}", {arg.name} if isinstance({arg.name}, bytes) else str({arg.name}).encode())'
			for arg in self.arguments
		])
		return result

class Argument:
	def __init__(self, name: str, sendafter: str) -> None:
		self.name = name
		self.sendafter = sendafter
