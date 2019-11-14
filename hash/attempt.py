#!/usr/bin/python3

import angr
import claripy

project = angr.Project('hashmenot')

argv = claripy.BVS("arg", 100*8)
state = project.factory.entry_state()
sm = project.factory.simulation_manager(state)

sm.explore(find=0x400a2b)

if sm.found:
	print(sm.found[0].posix.dumps(0))
else:
	print("No solutions found")

#print(repr(solution))


