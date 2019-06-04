#!/usr/bin/python3

import angr
import claripy

def main():
	print("file lock, stdin, find 0x4008a6, explore")

	while True:
		print(">> ", end="")
		cmd = input().split(" ")

		if cmd[0] == "file":
			project = angr.Project(cmd[1])
			state = project.factory.entry_state()
		if cmd[0] == "stdin":
			state = project.factory.entry_state()
			simgr = project.factory.simulation_manager(state)
		if cmd[0] == "find":
			if len(cmd) > 1:
				find_addr = int(cmd[1], 16)
		if cmd[0] == "explore":
			simgr.explore(find=find_addr)
			if simgr.found:
				print(simgr.found[0].posix.dumps(0))
			else:
				print("No solutions found")
		if cmd[0] == "exit":
			exit()

main()
