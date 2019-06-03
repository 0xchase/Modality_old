#!/usr/bin/python3

import angr
import claripy

project = angr.Project('baby2')

argv1 = claripy.BVS("argv1", 100*8)
state = project.factory.entry_state(args=["./baby2", argv1])
sm = project.factory.simulation_manager(state)

sm.explore(find=0x004031a3)

found = sm.found[0]

solution = found.solver.eval(argv1, cast_to=bytes)
solution = solution[:solution.find(b"\x00")]

print(repr(solution))


