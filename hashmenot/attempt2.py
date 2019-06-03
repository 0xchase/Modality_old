#!/usr/bin/python3

import angr
import claripy

project = angr.Project('hashmenot')

argv1 = claripy.BVS("argv1", 100*8)
state = project.factory.entry_state()
sm = project.factory.simulation_manager(state)

sm.explore(find=0x400a2b)

found = sm.found[0]

solution = found.solver.eval(argv1, cast_to=bytes)
solution = solution[:solution.find(b"\x00")]

print(repr(solution))


