#!/usr/bin/python3

import angr
import claripy

def main():
	print("Enter file: ", end='')
	myfile = input()
	project = angr.Project(myfile)
	state = project.factory.entry_state()
	
	while True:
		print(">> ", end="")
		cmd = input().split(" ")

		if cmd[0] == "stdin":
			state = project.factory.entry_state()
			simgr = project.factory.simulation_manager(state)
		if cmd[0] == "find":
			find_addr = 0x4008a6
		if cmd[0] == "explore":
			simgr.explore(find=find_addr)
			if simgr.found:
				print(simgr.found[0].posix.dumps(0))
			else:
				print("No solutions found")
		if cmd[0] == "exit":
			exit()

main()
