#!/usr/bin/python3

import angr
import claripy
import os

def help():
	print("file lock, input stdin, find 0x4008a6, explore, print stdin")
	print("file baby, input arg, find 0x004031a3, explore, print solution")

def main():
	help()
	while True:
		print(">> ", end="")
		cmd = input().split(" ")

		if cmd[0] == "file":
			project = angr.Project(cmd[1])
			state = project.factory.entry_state()
		if cmd[0] == "input":
			if cmd[1] == "stdin":
				state = project.factory.entry_state()
				simgr = project.factory.simulation_manager(state)
			if cmd[1] == "arg":
				argv1 = claripy.BVS("argv1", 100*8)
				state = project.factory.entry_state(args=["./baby", argv1])
				simgr = project.factory.simulation_manager(state)
		
		if cmd[0] == "find":
			if len(cmd) > 1:
				find_addr = int(cmd[1], 16)
		if cmd[0] == "explore":
			simgr.explore(find=find_addr)
			if simgr.found:
				print(simgr.found[0].posix.dumps(0).decode("utf-8"))
			else:
				print("No solutions found")
		if cmd[0] == "print":
			if cmd[1] == "stdin":
				print(simgr.found[0].posix.dumps(0).decode("utf-8"))
			if cmd[1] == "stdout":
				print(simgr.found[0].posix.dumps(1).decode("utf-8"))
			if cmd[1] == "solution":
				solution = simgr.found[0].solver.eval(argv1, cast_to=bytes)
				print(solution[:solution.find(b"\x00")].decode("utf-8"))
		if cmd[0] == "clear":
			os.system("clear")
		if cmd[0] == "exit":
			exit()

main()
