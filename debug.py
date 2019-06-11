#!/usr/bin/python3

import angr
import os
from IPython import embed

proj = angr.Project('lock', auto_load_libs=False)

state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

while True:
	address = str(simgr.active)[13:-2]

	print("[" + address + "]> ", end='')
	cmd = input().split(" ")
	
	if cmd[0] == "s":
		if len(cmd) > 1:
			for i in range(int(cmd[1])):
				simgr.step()
		else:
			simgr.step()
	if cmd[0] == "r":
		simgr.run()
	if cmd[0] == "i":
		embed()
	if cmd[0] == "states":
		print(simgr)
	if cmd[0] == "regs":
		print("rsp: " + str(state.regs.rsp))
		print("rax: " + str(state.regs.rax))
		print("rip: " + str(state.regs.rip))
		print("rbp: " + str(state.regs.rbp))
	if cmd[0] == "clear":
		os.system("clear")
	if cmd[0] == "exit":
		exit()
