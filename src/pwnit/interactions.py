from pwnit.utils import ask


class Interactions:
	def __init__(self, pwntube_variable: str, tab: str):
		self.pwntube_variable: str = pwntube_variable
		self.tab: str = tab
		self.functions: list[InteractionFunction] = []
		self.menu_recvuntil: str = ""

		self.menu_recvuntil = ask("Menu recvuntil (empty to finish interactions)")
		if not self.menu_recvuntil: return

		# Functions
		while True:
			function_name = ask("Function name (empty to finish interactions)")
			if not function_name: break
			self.functions.append(InteractionFunction(function_name))

	def dump(self, tab_placeholder: str):
		result = "".join([
			f"\n{tab_placeholder}{func.dump(self.pwntube_variable, self.menu_recvuntil, tab_placeholder+self.tab)}\n"
			for func in self.functions
		])
		return result


class InteractionFunction:
	def __init__(self, name: str):
		self.name = name
		self.arguments: list[Argument] = []
		
		# Option number
		self.send_to_select = ask("Send to select it", can_skip=False)
			
		# Arguments
		while True:
			argument_name = ask("Argument name (empty to end function)")
			if not argument_name: break
			argument_sendafter = ask("Send after", can_skip=False)
			self.arguments.append(Argument(argument_name, argument_sendafter))

	def dump(self, pwntube_variable: str, menu_recvuntil: str, tab: str):
		arguments = ", ".join(arg.name for arg in self.arguments)
		menu_recvuntil = menu_recvuntil.replace("\"", "\\\"")
		send_to_select = self.send_to_select.replace("\"", "\\\"")
		send_args = [
			f'{tab}{pwntube_variable}.sendlineafter(b\"' + arg.sendafter.replace("\"", "\\\"") + f'\", {arg.name} if isinstance({arg.name}, bytes) else str({arg.name}).encode())'
			for arg in self.arguments
		]
		result = "\n".join([
			f'def {self.name}({arguments}):',
			f'{tab}{pwntube_variable}.sendlineafter(b\"{menu_recvuntil}\", b\"{send_to_select}\")',
			*send_args,
		])
		return result

class Argument:
	def __init__(self, name: str, sendafter: str) -> None:
		self.name = name
		self.sendafter = sendafter
